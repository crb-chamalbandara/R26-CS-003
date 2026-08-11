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
      |-- Cookies SQLite database
      |-- Login Data SQLite database  (credentials decrypted via DPAPI + AES-GCM)
      |-- Downloads table
      |-- Extensions manifests
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

While a browser is running it holds an exclusive lock on its SQLite files. The
extractor first attempts a normal file copy; on a Windows sharing violation it
falls back to SQLite's **online backup API** through an immutable read-only URI
(`file:...?mode=ro&immutable=1`). This lets the engine read a consistent
snapshot of a live profile without corrupting it — a forensically sound
acquisition technique. Each source file's SHA-256 hash, size, and modification
time are recorded in an **artifact manifest** to preserve chain-of-custody.

### 4.2 DPAPI credential decryption

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

### 4.3 Local storage extraction

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

### 9.1 Detector correctness — unit test suite

`test/C4/test_correlation.py` drives eight synthetic attack scenarios (one per
detector plus a combined full-pipeline MITRE test) through the real pipeline and
asserts that the expected finding is produced.

**Result: 8/8 scenarios pass.**

| Scenario | Detector exercised | Outcome |
|----------|--------------------|---------|
| 1 | Co-occurrence | PASS |
| 2 | Orphan detection | PASS |
| 3 | Temporal anomaly | PASS |
| 4 | Attack chain | PASS |
| 5 | Domain risk clustering | PASS |
| 6 | Cross-domain credential reuse | PASS |
| 7 | Download → exfiltration | PASS |
| 8 | Full-pipeline MITRE mapping | PASS |

### 9.2 DPAPI decryption verification

The DPAPI + AES-256-GCM chain was verified end-to-end on a live Windows profile:
the 32-byte AES master key was successfully recovered from `Local State`, and a
known value encrypted in Chrome's exact `v10` blob format was decrypted back to
the original plaintext — confirming the full decryption path works against real
Chrome-format data.

### 9.3 End-to-end demonstration

`test/C4/demo_attack_profile.py` plants a coherent multi-stage breach (phishing
landing → drive-by download → credential theft → exfiltration callback → orphan
injection → cross-domain credential reuse) and runs it through the complete
pipeline.

**Result: all 7/7 detectors fire**, producing 25 MITRE-mapped findings
(13 High, 11 Medium, 1 Low) and a full HTML/JSON/SIEM report.

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
forensic correlation engine. It extracts and normalizes six artifact types
(including DPAPI-decrypted credentials and local storage), applies seven
cross-table correlation detectors over a 120-second sliding window, maps every
finding to MITRE ATT&CK, and exports analyst-ready JSON, HTML, and SIEM reports.
Both the unit-test suite (8/8) and the end-to-end demonstration (7/7 detectors
firing) confirm that the engine reconstructs multi-stage attack timelines that
single-artifact forensic tools cannot — answering the research question in the
affirmative.
