# Component 4 — Browser Artifact Forensic Correlation Engine

**Research Project:** R26-CS-003 — *Browser Security Intelligence: A Multilayer Browser Threat Detection and Prevention System*
**Component owner:** S.A.O.D. Sandeepa (IT22252104)
**Research group / specialization:** Information Assurance & Security (IAS) — Cyber Security

---

## 1. Introduction

Multi-stage browser attacks do not leave their evidence in one place. A single
intrusion scatters traces across several independent browser data stores —
browsing history, cookies, saved credentials, download records, installed
extensions, and local storage — and each of these is held in a separate SQLite
database or LevelDB store with its own schema and its own timestamp format.
Traditional browser-forensic tools such as Hindsight extract these artifacts,
but they examine each artifact type *in isolation*. A cookie is reported as a
cookie and a download as a download; the relationship *between* them — that a
credential was saved, a session cookie appeared for a domain that was never
visited, and a suspicious executable was downloaded, all within the same two
minutes — is never surfaced.

Component 4, the **Browser Artifact Forensic Correlation Engine**, closes this
gap. It normalizes heterogeneous browser artifacts into a single unified event
timeline and applies **seven cross-table correlation detectors** over a sliding
time window to reconstruct suspicious activity that is invisible to
single-artifact analysis. Every finding is mapped to a
**MITRE ATT&CK** technique and exported as a JSON, HTML, and SIEM-compatible
forensic report.

### 1.1 Research question

> Can automated cross-artifact correlation of browser forensic data reliably
> reconstruct suspicious activity timelines and map findings to MITRE ATT&CK
> techniques?

---

## 2. Objectives

**Sub-objective:** Design and implement a forensic correlation engine that links
browser artifacts across multiple data stores within a bounded time window to
identify multi-stage attack patterns.

The concrete tasks committed to in the project's Topic Assessment Form were:

1. Parse all major browser artifact files — history, cookies, downloads,
   credentials, local storage, and session data — and **decrypt DPAPI-protected
   credential stores**.
2. Build a **sliding-window correlation engine** that links events across
   artifact types within **120-second** windows and scores them against known
   multi-stage attack patterns.
3. Implement **seven cross-table forensic signal detectors** that correlate data
   across separate Chromium SQLite databases and LevelDB stores.
4. Generate unified timeline reports with **MITRE ATT&CK** technique mapping,
   severity scoring, and JSON export for SIEM integration.

---

## 3. System Architecture

The engine is a five-stage pipeline. Each stage consumes the output of the
previous one, so the design is modular and each stage can be tested in
isolation.

```
Browser profile directory
      |-- History SQLite database
      |-- Cookies SQLite database     (or the live jar when the browser holds the lock)
      |-- Login Data SQLite database  (credentials decrypted via DPAPI + AES-GCM)
      |-- Downloads table
      |-- Extensions manifests + the Secure Preferences extension registry
      |-- Sessions SNSS store         (tabs the browser would restore)
      |-- Local Storage LevelDB store
      v
[1] Artifact Extractor        -> normalizes every artifact into a common event schema
      v
[2] Single-Artifact Rule Engine -> flags individually suspicious events
      v
[3] Cross-Artifact Correlation  -> 7 cross-table detectors over a 120s window
      v
[4] MITRE ATT&CK Mapper         -> assigns technique, tactic, severity
      v
[5] Reporter                    -> JSON report, HTML forensic report, SIEM export
```

### 3.1 Common event schema

Every extracted artifact is normalized into a single dictionary so that the
downstream stages never need to know which store an event came from:

```python
{
  "timestamp":       ISO-8601 string,
  "artifact_type":   "history" | "cookie" | "download" | "credential"
                      | "extension" | "localstorage",
  "source_file":     originating artifact store,
  "detail":          type-specific fields (url, host, origin, filename, ...),
  "risk_flag":       bool,
  "anomaly_score":   int,
  "anomaly_reasons": [str],
  "rule_flags":      [rule hits]
}
```

This normalization is what makes cross-table correlation possible: a history
URL, a cookie host, a credential origin, and a download source URL are all
reduced to a comparable **domain** key.

---

## 4. Stage 1 — Artifact Extraction

### 4.1 Safe acquisition of locked databases

While a browser is running it holds its SQLite files open. The extractor first
attempts a normal file copy; on a Windows sharing violation it falls back to
SQLite's **online backup API** through an immutable read-only URI
(`file:...?mode=ro&immutable=1`), which reads a consistent snapshot without
writing to or corrupting the original. Each source file's SHA-256 hash, size,
and modification time are recorded in an **artifact manifest** to preserve
chain-of-custody, and re-hashing after analysis confirms the evidence is
unchanged.

The two files are not locked the same way, which matters. `History` is opened
share-read, so the backup path recovers it from a live profile. `Network/Cookies`
is opened with an exclusive share mode: the handle cannot be obtained at all, so
`copy2`, `immutable=1` and `nolock=1` all fail and *no* file-based technique
recovers a cookie while the browser is up. For that store the engine performs
**volatile acquisition** instead — the cookie jar is read from the running
browser through the automation channel and normalized into the same event
schema, tagged `acquisition: "live"` so the provenance of every cookie event
stays explicit in the report.

### 4.2 Extension acquisition beyond the Extensions folder

An extension loaded with `--load-extension` — the standard side-loading route,
and the one an attacker uses — creates no `Default/Extensions/<id>/` folder.
Its record, including the full manifest and requested permissions, exists only
in the `Secure Preferences` extension registry. The extractor reads both sources
and de-duplicates by extension ID, and decodes the `location` field, so an
`unpacked` install is reported as a finding in its own right, separately from
the permissions it asks for.

### 4.3 DPAPI credential decryption

Chrome never stores saved passwords in plaintext. From Chrome 80 onward, each
password in the `Login Data` database is encrypted with **AES-256-GCM**, and the
AES master key itself is stored — protected by the Windows **Data Protection API
(DPAPI)** — inside the profile's `Local State` JSON file. The decryption chain
implemented in `crypto.py` is:

1. Read `os_crypt.encrypted_key` (base64) from `Local State`.
2. Strip the 5-byte `DPAPI` prefix and call `CryptUnprotectData` to recover the
   32-byte AES master key. DPAPI is invoked directly through `ctypes`
   (`crypt32.dll`), avoiding any third-party dependency.
3. For each password blob of the form
   `b"v10"|b"v11" + nonce(12) + ciphertext + tag(16)`, decrypt with AES-256-GCM
   using the master key. Legacy pre-Chrome-80 blobs are DPAPI-encrypted directly
   and recovered by `CryptUnprotectData` alone.

Because DPAPI keys are bound to the current Windows user account, decryption
only succeeds when the engine runs as the same user that owns the profile —
which is precisely how the forensic engine is deployed. **Responsible-forensics
design:** decrypted passwords are stored *masked* (first and last character plus
length, e.g. `h******3`) in on-disk reports by default, so the persisted
forensic artifacts never contain live plaintext credentials while still proving
that decryption succeeded.

### 4.4 Session-restore extraction

`Default/Sessions/Session_*` and `Tabs_*` record the tabs the browser would
restore and the URLs in their navigation stacks. They are written independently
of the History database, so a tab can outlive its own history entry — a URL that
is restorable but has no visit record is evidence in itself, and Stage 3 scores
it as an orphan. The SNSS container is a versioned command log whose command IDs
change between Chromium builds, so instead of decoding the log the extractor
recovers the URL strings in both encodings Chromium writes (UTF-8 and UTF-16LE),
de-duplicates them, and timestamps each from the Chrome timestamp embedded in
the session filename. The session in progress is held open by the running
browser and is reported as a warning rather than treated as a failure.

### 4.5 Local storage extraction

Chrome stores per-origin local storage in a LevelDB database. A full LevelDB
decode is out of scope, but the extractor scans the uncompacted `.log`/`.ldb`
records to recover which **origins** hold local-storage state. An origin with
stored state but no corresponding browsing history becomes an *orphan* candidate
in Stage 3 — a signal that a script planted state for a site the user never
actually visited.

---

## 5. Stage 2 — Single-Artifact Rule Engine

Before correlation, six rules flag individually suspicious events so that the
correlation stage can boost the score of clusters that already contain
known-bad events:

| Rule | Signal | Example MITRE technique |
|------|--------|-------------------------|
| R01 | Suspicious domain in history (e.g. `pastebin`, `ngrok.io`) | T1566.002 Spearphishing Link |
| R02 | Dangerous download extension (`.exe`, `.ps1`, `.scr`, …) | T1204.002 Malicious File |
| R03 | Sensitive session-cookie name (`session`, `jwt`, `bearer`) | T1539 Steal Web Session Cookie |
| R04 | Saved credential record | T1555.003 Credentials from Web Browsers |
| R05 | Risky extension permissions (`<all_urls>`, `debugger`, …) | T1176 Browser Extensions |
| R06 | URL burst — ≥20 URLs in 60 s (bot/malware pattern) | T1056 Input Capture |

---

## 6. Stage 3 — Cross-Artifact Correlation (7 Detectors)

All seven detectors operate over a **120-second sliding window** (`WINDOW_SECONDS
= 120`). This is the core novelty of the component: each detector correlates
data *across separate browser stores* in a way that a single-artifact tool
cannot.

| # | Detector | Cross-table relationship | Intuition |
|---|----------|--------------------------|-----------|
| A | **Co-occurrence** | history × cookie × credential × download | The more artifact types touch the *same domain* within the window, the higher the risk. |
| B | **Orphan detection** | cookie / credential / download / localstorage × history | An artifact for a domain with **no browsing history** suggests injection rather than genuine user activity. |
| C | **Temporal anomaly** | any artifact × personal history baseline | Learns the *user's own* hourly activity profile and flags events at hours the user is normally inactive — personalised, not a generic "2 a.m. is bad" rule. |
| D | **Attack-chain** | ordered history → download → credential (and other orders) | Detects an *ordered* sequence on the same domain, stricter than co-occurrence. |
| E | **Domain risk clustering** | all artifact types per domain | Scores each domain by artifact diversity, flagged-event count, and accumulated rule score. |
| F | **Cross-domain credential reuse** | logins × logins | The same saved username on **two or more different domains** — one stolen password unlocks several accounts. |
| G | **Download → exfiltration** | downloads × history | A file download followed within the window by outbound navigation to a **different** domain — the classic "drop tool, then call home / upload" step. |

Detectors **F** and **G** are the two signals added to reach the seven committed
in the proposal. They directly model the flagship attack narrative from the
project's novelty statement: *a credential is stolen, the same credential
appears on a different domain, and a download is followed by network
exfiltration — all within seconds.*

Each detector produces a finding with a numeric score (0–100); detectors also
write back `anomaly_score` and human-readable `anomaly_reasons` onto the
individual events, so the flagged-event timeline explains *why* each event was
flagged.

---

## 7. Stage 4 — MITRE ATT&CK Mapping

Every correlation finding and every rule flag is mapped to a MITRE ATT&CK
technique with a tactic and a **Low / Medium / High** severity. Representative
mappings:

| Pattern | Technique |
|---------|-----------|
| Cookie + credential co-occurrence | T1539 Steal Web Session Cookie |
| History + cookie + credential | T1185 Browser Session Hijacking |
| Browser credential records | T1555.003 Credentials from Web Browsers |
| Dangerous download | T1204.002 Malicious File |
| Orphan download | T1105 Ingress Tool Transfer |
| Risky extension permissions | T1176 Browser Extensions |
| Cross-domain credential reuse | T1078 Valid Accounts |
| Download then outbound navigation | T1567 Exfiltration Over Web Service |

The mapper aggregates findings by severity and returns a single ranked
`all_findings` list that drives both the HTML report and the SIEM export.

---

## 8. Stage 5 — Reporting and Integration

The reporter produces three outputs:

1. **JSON report** — the complete result object (events, correlation findings,
   MITRE mappings, manifest) for archival and further processing.
2. **HTML forensic report** — an executive summary, artifact manifest with
   hashes, a MITRE ATT&CK findings table, and a colour-coded flagged-event
   timeline.
3. **SIEM export** — each finding as a normalized event with standard fields
   (`mitre_technique_id`, `severity`, `score`, …) compatible with
   Splunk / QRadar / ELK ingestion.

The engine is integrated into the WebSentinel FastAPI backend (`core/main.py`)
and exposed through `/forensic/*` endpoints (`/extract`, `/summary`,
`/timeline`, `/mitre`, `/report/html|json|siem`), so its findings appear in the
unified multi-component dashboard alongside the other three components.

---

## 9. Evaluation

### 9.1 Function correctness — unit test suite

`test/C4/test_units.py` exercises the modules around the correlation engine one
function at a time: timestamp conversion, evidence hashing, profile resolution
and SQLite parsing in `extractor.py`; every `decrypt_password` status branch in
`crypto.py`; rules R01–R06 in isolation; HTML/SIEM generation in `reporter.py`;
and the risk-score bands in `service.py`. Each case asserts both that a signal
fires when it should and that it stays silent when it should not.

**Result: 55/55 cases pass.**

### 9.2 DPAPI decryption verification

The DPAPI + AES-256-GCM chain is verified end-to-end against Chrome-format data.
The evaluation case seals a freshly generated 32-byte AES master key with
`CryptProtectData`, stores it in `Local State` exactly as Chrome does, and writes
each password as a genuine `v10` + nonce + AES-GCM blob into `Login Data`. C4
then recovers the key through `CryptUnprotectData` and decrypts every record.

**Result: 3/3 credentials recovered** on a live Windows account. Because the key
is DPAPI-bound, the same evidence yields `no-key` under any other account — the
correct forensic outcome, and the reason reports store only a masked preview
(`P**************6`), status and length rather than plaintext.

### 9.3 End-to-end demonstration on real evidence

`test/C4/demo_attack_profile.py` (case builder in `core/c4/demo_case.py`) plants a
coherent multi-stage breach and runs the *unmodified* production pipeline over
it. The evidence is written to disk as real Chrome-schema SQLite databases, real
encrypted credential blobs, a real dropped file and real LevelDB records, so the
detectors receive events parsed by `run_extraction()` rather than hand-built
dictionaries — the same code path a scan of a seized profile takes.

The planted case is two weeks of ordinary 09:00–17:00 browsing (224 visits)
overlaid with an automated 25-URL harvesting burst, a 03:00 phishing landing,
a drive-by `.exe` drop, credential theft, an exfiltration callback, injected
cookie/localStorage state for a never-visited domain, and one password reused
across three corporate domains.

**Result: 37/37 checks pass and all 7/7 detectors fire** on 277 extracted events
(252 history, 8 cookie, 3 credential, 2 download, 4 extension, 6 session tab,
2 localStorage):

| Detector | Finding on the planted case | Score |
|----------|-----------------------------|-------|
| A · Co-occurrence | 5 artifact types on `secure-payroll-login.top` in 2 min | 100 |
| B · Orphan detection | cookie + localStorage for a never-visited domain, and an open tab whose domain appears in no history entry | 40–55 |
| C · Temporal anomaly | 7 artifacts at 03:00 vs a 09:00–17:00 personal baseline | 40–70 |
| D · Attack chain | ordered browse → download → credential | 96 |
| E · Domain risk clustering | breach domain ranks #1 of 5 | 100 |
| F · Credential reuse | one identity saved on 3 domains | 85 |
| G · Download → exfiltration | `payroll_update.exe` drop, then outbound navigation 90 s later | 60 |

Rules R01–R06 all fire, while 257 of 277 events stay unflagged — the engine
discriminates rather than blanket-flagging. The 23 correlation findings map to
10 MITRE techniques across 9 tactics (9 High, 14 Medium), aggregating to a risk
score of 72.6/100, verdict **HIGH**. Re-hashing the source files after the run
confirms all five evidence files are byte-identical, and the run reports
**67/67 tracked C4 functions executed**, measured by wrapping each function
during the run rather than by assertion.

### 9.4 Acquisition against a *live* profile

Evaluating C4 against the browser profile the system is actually driving exposed
three acquisition problems that a post-mortem, browser-closed evaluation hides.
All three are now handled, and each was measured on the live profile:

**Cookies are unreadable from disk while the browser runs.** Chromium holds
`Network/Cookies` open with an exclusive Windows share mode for its entire
lifetime. `shutil.copy2` fails with a sharing violation, and so does SQLite's
`immutable=1` read-only URI and `nolock=1` — the handle cannot be opened at all,
so no file-based technique recovers a single cookie. C4 therefore falls back to
*volatile acquisition*: the cookie jar is read out of the running browser
through the automation channel and converted into the same event schema, tagged
`acquisition: "live"` so a report never implies the events came off the file.
Measured on a live Chromium: 0 cookies file-only, 3/3 recovered live.

**A side-loaded extension leaves no `Extensions/` folder.** Extensions started
with `--load-extension`, the standard automation and malware side-loading route,
are recorded only in `Secure Preferences` → `extensions.settings`, with their
full manifest. Reading the folder alone reports "no extensions" on exactly the
profiles where a hostile extension is most likely to be present. C4 now reads
both sources and de-duplicates by extension ID, and treats an `unpacked`
install location as a finding in its own right, independent of the permissions
requested. Measured on the live profile: 0 extensions from the folder, 3
recovered from the registry.

**Session-restore data is a separate evidence source from history.**
`Sessions/Session_*` and `Tabs_*` hold the tabs the browser would restore and
every URL in their back/forward stacks. Because they are written independently
of the History database, a tab can survive a cleared history — a URL that is
restorable but has no visit record is a strong signal on its own, and is scored
as an orphan (55). The SNSS container is a versioned command log, so rather
than depending on the command IDs of one Chromium build, C4 recovers the URL
strings in both encodings Chromium writes them in (UTF-8 and UTF-16LE) and
timestamps each from the session filename. Measured on the live profile: 103
restorable tab URLs across 16 hosts; the in-progress session file is held open
by the browser and is reported as a warning rather than a failure.

### 9.5 Live demonstration in the dashboard

The same case drives the dashboard's Live Test Runner panel (`C4 Only`), which
streams 21 rows over SSE. The first five read the live browser profile this
session is actually driving — history, cookies acquired from the session,
the Login Data store with its DPAPI master-key recovery, extensions from the
registry, and restorable tabs — and the remaining rows walk the planted case
one pipeline stage at a time: extraction, credential decryption, the rule
engine, each of the seven detectors individually, MITRE mapping, report
generation, verdict, evidence integrity and function coverage. Each row prints
the concrete finding it produced, so the panel demonstrates *why* the component
reached its verdict rather than only that its tests pass.

---

## 10. Novelty and Contribution

This component is, to our knowledge, the first to perform **simultaneous
cross-table temporal correlation across all major browser artifact types** in a
unified engine. The specific contributions are:

- **Seven cross-table detectors** that surface relationships — orphan artifacts,
  credential reuse, download-to-exfiltration chains — that are structurally
  invisible to single-artifact tools such as Hindsight.
- A **personalised temporal baseline** that learns each user's own activity
  rhythm instead of applying a fixed "unusual hour" threshold.
- **Integrated DPAPI + AES-256-GCM credential decryption** implemented with a
  responsible-forensics masking default.
- **Automatic MITRE ATT&CK mapping** of every finding, turning raw artifacts
  into an analyst-ready, SIEM-exportable attack narrative.

---

## 11. Limitations and Future Work

- **Local storage decoding** currently recovers origins and entry counts via a
  raw record scan; a full LevelDB block/snappy decoder would additionally
  recover stored key–value contents.
- **DPAPI decryption is Windows-specific.** macOS (Keychain) and Linux
  (`gnome-keyring`) credential stores would each require a platform-specific
  backend.
- **Correlation thresholds** (the 120-second window, score weights) are
  currently fixed constants informed by the attack scenarios; a labelled
  real-world corpus could be used to tune them empirically.
- Detector **G** pairs a download with the first subsequent cross-domain
  navigation; richer exfiltration modelling could weight the destination by
  reputation or beaconing regularity (in cooperation with Component 3).

---

## 12. Conclusion

Component 4 delivers a complete, tested, and integrated browser artifact
forensic correlation engine. It extracts and normalizes seven artifact types
(history, cookies, downloads, DPAPI-decrypted credentials, extensions,
session-restore tabs and local storage), applies seven cross-table correlation
detectors over a 120-second sliding window, maps every finding to MITRE ATT&CK,
and exports analyst-ready JSON, HTML, and SIEM reports. It acquires all of them
from a *running* browser, where the cookie store is locked, side-loaded
extensions leave no folder, and the session in progress is held open. The unit
suite (55/55), the end-to-end demonstration on planted evidence (37/37 checks,
7/7 detectors firing) and the live-profile rows in the dashboard together
confirm that the engine reconstructs multi-stage attack timelines that
single-artifact forensic tools cannot — answering the research question in the
affirmative.
