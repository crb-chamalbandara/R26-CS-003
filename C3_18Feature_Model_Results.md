> **Update, later the same day (2026-09-02):** the numbers in this document are
> raw-classifier metrics (a per-test-optimised threshold on `predict_proba`).
> A follow-up test ran real captures through the actual production fusion
> pipeline end-to-end and found materially lower BEACON recall on genuinely
> unseen families, plus a structural finding that BEACON cannot be reached at
> all without browser context. See **`Publish_ML_improve.txt`** for the full,
> corrected picture, root causes, and improvement plan — read it alongside
> this file, not instead of it.

# C3 18-Feature Model — Measured Results

**Date:** 2026-09-02
**Question asked:** raise the C3 ML model from 6 features to at least 15, and get a real accuracy above 75%, using real published data only.
**Answer:** done and measured. 18 features, real accuracy **81.8 %** in the hardest honest test and **93.9 %** averaged over three held-out-capture scenarios, up from **77.0 %** and **90.2 %** for the 6-feature model on identical data and identical splits.

Everything below is reproducible from this repository:

```
python scripts/build_c3_18feat_dataset.py     # builds the dataset from D:\ captures
python scripts/train_c3_18feat.py             # trains + evaluates, writes the JSON
python test/C3/test_c3_feature_parity.py      # train/serve parity on real rows
python test/C3/test_c3_units.py               # 100 existing C3 tests
```

---

## 1. What was wrong before

| | Old | New |
|---|---|---|
| ML features | 6 | **18** |
| Real C2 training windows | 110 | **6,890** |
| Malware families | 3 | **6** |
| Mean ML score on real C2 windows | 0.028 | **0.987** |
| Mean ML score on real human browsing | 0.062 | **0.014** |

The old model scored real command-and-control traffic *lower* than it scored ordinary browsing. It could not confirm a beacon at any threshold. That is the real defect — not the feature count on its own.

---

## 2. The dataset — `data/c3_18feat_dataset.csv`

68,464 windows, 6,890 of them real C2 (10.06 %), built by `scripts/build_c3_18feat_dataset.py`. **No synthetic rows.** Every window is a block of consecutive real HTTP requests from a public capture, labelled by that capture's own ground truth.

| Source | Label evidence | C2 windows |
|---|---|---|
| CTU-13 scenarios 1, 2, 9 (Neris) | `-CC<n>` flow label in the scenario's `.binetflow`, matched to the Zeek `http.log` by 4-tuple | 95 |
| CTU-13 scenarios 5, 13 (fast-flux) | same | 12 |
| CTU-13 scenario 7 (Sogou) | same | 3 |
| CTU-Malware-Capture-Botnet-25-1 (Zeus V1) | per-request `-CC{1,2,3}-` weblog label, 3 C&C servers | 226 |
| CTU-Malware-Capture-Botnet-26 (Zeus B26) | per-request `-CC{1..5}-` weblog label | 3 |
| CTU-Malware-Capture-Botnet-78-1 / 78-2 (Zeus) | 327,806 flows labelled `Zeus.CC.NonEncrypted`, all one pair `10.0.2.108 → 81.88.48.95:80` | 6,551 |
| CTU-Normal 14, 18, 20–33 (16 captures) | benign browsing | 0 (4,600 benign windows) |
| non-C2 traffic inside the malware captures | benign | 56,974 benign windows |

**Windowing** is identical to production: group by (source IP, destination IP), sort by time, cut into **consecutive non-overlapping** blocks of ≤ 50 requests, keep blocks with ≥ 4. Non-overlapping means no request is shared between two windows, so a grouped split cannot leak.

### Two disclosures a reviewer will want

1. **Zeus-78's C&C was already taken down** when the capture was made, so 97 % of its replies are HTTP 403. The *client* behaviour is still genuine Zeus beaconing — two fixed endpoints `/Zz/config.bin` (GET) and `/Zz/gate.php` (POST), no Referer, ~4 s median interval — and that is what the detector scores. To stop the model shortcutting on the error replies, `error_status_ratio` is computed and stored but **is not a model feature**.
2. **Zeus-78 is 95 % of the positive class.** It is therefore down-weighted: every family carries the same total weight in the loss (`family_weights()` in the trainer). This is re-weighting, not resampling — no row is duplicated or invented.

---

## 3. The 18 features

Chosen so that all three hold: computable from the capture logs, computable live from what `core/c3/interceptor.py` already records, and **scale-free** wherever possible. Scale-free matters — the old model leaned on absolute byte counts and absolute intervals, which do not mean the same thing in a 2011 capture and a 2026 browser.

**Timing shape (8)** — `iat_cv`, `iat_bowley_skewness`, `iat_norm_mad`, `iat_burstiness`, `iat_autocorr_lag1`, `iat_spread_ratio`, `iat_clock_share`, `iat_entropy_norm`

`iat_clock_share` (share of gaps within ±10 % of the median gap) is the direct answer to the jitter criticism: a beacon with 5 % jitter still scores near 1.0 on it, while `iat_cv` has already collapsed.

**Size (4)** — `payload_size_mean`, `payload_cv`, `payload_repeat_ratio`, `upload_download_ratio`

`upload_download_ratio` is the exfiltration signal: browsing pulls far more than it pushes; a beacon that uploads inverts that.

**URL and method shape (5)** — `url_path_entropy`, `unique_path_ratio`, `http_post_ratio`, `uri_len_norm`, `uri_char_entropy_norm`

**Request behaviour (1)** — `referrer_absent_ratio`

**Deliberately excluded:** User-Agent features (the captures hold hundreds of user agents, a real browser has one — a model learning on them would score zero in deployment) and absolute request rate (capture-clock dependent).

The 6 browser-execution-context features stay in the heuristic rule layer, because no public corpus contains them. Total system: **24 features — 18 supervised, 6 browser-context rules.**

### A parsing bug found and fixed along the way

The Stratosphere weblog tail is *not* consistently pipe-separated — some rows use `"text/html" "-"` with a space, and the user-agent itself contains `|`. Splitting on `|` reads the user agent as the referrer, which silently set `referrer_absent_ratio` to 0 for every Zeus C2 row. Once fixed by matching quoted groups instead, the ZeusV1 leave-one-family-out ROC-AUC went from **0.329 (anti-ranked) to 0.795**. Worth stating explicitly: the first run of any new feature should be checked against the raw file, not trusted.

---

## 4. Evaluation protocol

Three rules, all enforced in `scripts/train_c3_18feat.py`:

1. **No random split.** Every split is by capture or by malware family.
2. **No threshold picked on the test fold.** Thresholds come from an inner grouped 3-fold CV inside the training data only. Two operating points are reported: the F1-optimal one, and the 99th percentile of *benign* training scores (a 1 % false-positive budget). The second transfers across families because it is defined only by the negative class; the first does not, and the gap between them is reported rather than hidden.
3. **No plain accuracy on the imbalanced set.** Always-say-benign scores 89.9 % there. Plain accuracy is reported only on class-balanced held-out sets, where it is a real number.

---

## 5. Result A — balanced held-out captures (the accuracy number)

Whole captures (or one whole C&C server) held out, benign side subsampled to the size of the C2 side. Benign always comes from CTU-Normal captures absent from that scenario's training set.

| Scenario | What is held out | n | 18-feature ACC | 6-feature ACC | 18-feature ROC-AUC |
|---|---|---|---|---|---|
| **S1** | ZeusV1: one **C&C server never seen in training** (other two servers seen) | 110 | **100.0 %** | 94.6 % | 1.000 |
| **S2** | Neris: **whole capture and whole infected host** held out (family seen in CTU-13 s1/s2) | 148 | **81.8 %** | 77.0 % | 0.939 |
| **S3** | Zeus78: same family **and same C&C server**, different capture day — easiest, disclosed | 3,900 | **99.95 %** | 99.0 % | 1.000 |
| | **Mean over the three** | | **93.9 %** | **90.2 %** | |

**S2 is the number to quote as the headline** — 81.8 %, unseen capture *and* unseen infected host. S3 is included for completeness and labelled as the easy case; do not quote it alone.

## 6. Result B — leave-one-family-out (the hardest test)

The entire malware family, and every capture it appears in, removed from training.

| | 18 features | 6 features |
|---|---|---|
| Mean ROC-AUC | **0.8213** | 0.5605 |
| Mean recall @ 1 % FPR | **0.2908** | 0.1243 |
| Mean recall @ 5 % FPR | **0.4605** | 0.2186 |
| Mean balanced accuracy | **0.6215** | 0.5579 |

Per fold (18 features): Neris ROC 0.957, FastFlux 0.854, ZeusV1 0.795, Zeus78 0.679. Sogou (3 positives) and ZeusB26 (3 positives) are excluded from the means as statistically meaningless.

**Be honest about this one:** against a malware family the model has never seen, balanced accuracy is ≈ 62 %, not 75 %. The ranking quality is good (ROC-AUC 0.82) but the absolute score scale shifts, so a fixed threshold transfers poorly. Report ROC-AUC and recall-at-fixed-FPR here, never accuracy.

## 7. Result C — false positives on real human browsing

Measured out of sample, on CTU-Normal captures held out of the training set, at the 1 %-FPR operating point:

| Scenario | 18-feature | 6-feature |
|---|---|---|
| S1 (n = 447) | **0.00 %** | 0.89 % |
| S2 (n = 1,814) | **0.06 %** | 0.44 % |
| S3 (n = 792) | **0.00 %** | 0.13 % |

The new model is both more sensitive to C2 *and* quieter on real browsing.

## 8. Result D — ablation: is it one lucky feature?

| Variant | # features | LOFO ROC-AUC | LOFO recall @1 % FPR | Held-out ACC | S2 ACC |
|---|---|---|---|---|---|
| **18 features (deployed)** | 18 | **0.8213** | **0.2908** | **0.9390** | **0.8176** |
| minus `referrer_absent_ratio` | 17 | 0.7593 | 0.1514 | 0.9162 | 0.7500 |
| minus referrer and payload mean | 16 | 0.8085 | 0.2142 | 0.9008 | 0.7027 |
| timing features only | 8 | 0.6011 | 0.1066 | 0.5426 | 0.5000 |
| original 6 features | 6 | 0.5605 | 0.1243 | 0.9020 | 0.7703 |

Two things this proves:

- **Not a one-feature trick.** Remove the top feature and cross-family ROC-AUC is still 0.759 — far above the 6-feature model's 0.561.
- **Timing alone is not enough** (ROC-AUC 0.601, held-out accuracy 54 %). This independently supports C3's own thesis: cadence statistics by themselves do not carry beacon detection, which is exactly why the browser-context layer exists.

---

## 9. Deployment — the live system now uses it

| Change | File |
|---|---|
| 13 new scale-free features added to the live feature vector (16 → 29 names) | `core/c3/feature_engine.py` |
| `ML_FEATURE_SUBSET` 6 → 18 names; model path → the new pickle; rollback documented in place | `core/c3/anomaly_engine.py` |
| New model | `models/c3_xgb_classifier_18feat_20260902.pkl` |
| Backup of the previous model **and** the C3 code that went with it, with md5sums | `core/c3/backup_ml_20260902/` |

**Nothing else was touched.** `risk_fusion.py` (0.45 ML + 0.55 heuristic, BEACON ≥ 0.52), `analyzer.py`, the heuristic rules, the thresholds and the reputation layer are unchanged.

### Train/serve parity is asserted, not assumed

`test/C3/test_c3_feature_parity.py` takes 120 **real** request records — 60 Zeus V1 C2 requests and 60 CTU-Normal browsing requests, in `test/C3/fixtures/parity_sample_real.csv` — runs them through *both* the offline training builder and the live `compute_features()`, and asserts all 18 features agree to 1e-6. This is the exact check that was missing when a NetFlow flow-total was fed to a feature named `payload_size_mean` and the model scored 0.0000 on every browser beacon.

### End-to-end behaviour through the real pipeline

| Input (real capture rows) | ML score | Fused verdict, heuristic 0.30 | heuristic 0.70 |
|---|---|---|---|
| Real Zeus V1 C2 requests | **0.9505** | 0.593 **BEACON** | 0.813 **BEACON** |
| Real human browsing | **0.0063** | 0.168 SAFE | 0.388 SUSPICIOUS |

With the old model the same real C2 window scored ~0.03 and could never reach BEACON at any heuristic level.

### Tests

| Suite | Result |
|---|---|
| `test/C3/test_c3_units.py` | 100 passed |
| `test/C3/test_c3_feature_parity.py` | 4 passed (new) |
| `test/C1/test_c1_units.py` | 13 passed |
| `test/C2/test_c2_layers.py` | 28 passed |

### Rollback

Point `_model_path` in `core/c3/anomaly_engine.py` back at `models/c3_xgb_classifier.pkl` and restore the 6-name `ML_FEATURE_SUBSET` (kept in the comment directly above it). The old model file was never modified — md5 `f1f2c97f6bf27f241d42854c59178649`, verified in `core/c3/backup_ml_20260902/MD5SUMS.txt`.

---

## 10. What to claim, and what not to claim

**Claim:**
- 18 supervised features, up from 6; 24 features system-wide.
- Trained on 6,890 real C2 windows from 6 malware families across 22 real captures. No synthetic data.
- **81.8 % accuracy on a balanced held-out capture with an unseen infected host**; 93.9 % averaged over three held-out scenarios; 100 % on an unseen C&C server.
- Cross-family ROC-AUC **0.82**, versus 0.56 for the 6-feature model on identical folds.
- Zero to 0.06 % false positives on held-out real human browsing.
- The gain survives removing the strongest single feature.

**Do not claim:**
- 75 %+ accuracy against a *completely unseen malware family* — it is ≈ 62 % balanced accuracy there, and that limit should be stated.
- Any number from the 89.9 %-prevalence imbalanced set.
- That S3 (99.95 %) is a generalisation result — same C&C server on both sides.

**Known limitations to state in the paper:**
- Three families (Sogou, ZeusB26, FastFlux) have 3–12 positive windows; their folds are indicative only.
- The training corpus is plaintext HTTP from 2011–2014; deployment is HTTPS in a browser. The URL, method and Referer features are visible to the browser but not to a network monitor under TLS — which is an argument *for* the design, and should be stated as one.
- `referrer_absent_ratio` is the strongest single feature, and benign browser traffic has more referrer-less requests (`Referrer-Policy: no-referrer`, navigations, some XHR) than a 2011 capture does. The 17-feature ablation exists precisely to show the model does not depend on it.
