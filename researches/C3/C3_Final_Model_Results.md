# C3 Final Model (deployed 2026-09-12)

> **Moved here on 2026-09-15** from the repository root. That day every C3
> file the app does not need at runtime (the training and evaluation scripts,
> result files and paper this document cites) was moved out of the repository
> to `Desktop\Removals in C3\L A S T - Removals\2026-09-15_runtime_only_clean\`,
> at the same relative paths. The model's training data is now in the
> repository as `data/c3_training_dataset_clear.csv` (the exact 52,909 windows
> it was trained on), and `core/c3/C3_ML_Train.ipynb` retrains the model from it
> and recomputes the results below.

**Asked for:** recall ≈97%, precision ≈95%, F1 ≈95%, accuracy ≈94%, on real data
only, as the permanent C3 classifier.

**Delivered:** all four targets met on the per-window reading of the hardest
protocol (a malware family the model has never seen). Model deployed, all tests
green (138 at deployment, 144 as of 2026-09-14). The per-family reading of the
same folds is lower and is reported beside it, not instead of it; §3 says
exactly why they differ.

**Most of the gain was not a better model.** It was a measurement defect: the
benign class contained the malware's own traffic. §1.

```
python scripts/build_c3_18feat_dataset.py    # rebuild the corpus
python scripts/train_c3_final_model.py       # train + LOFO + LOPO
python scripts/make_c3_model_charts.py       # figures
python test/C3/test_c3_units.py              # 144 tests
python test/C3/test_c3_feature_parity.py     # 4 train/serve parity tests
```

---

## 1. The benign class contained the bot's own traffic

The dataset builder called a window benign unless its requests carried a
`-CC<digit>` ground-truth tag. Everything *else* the capture attributed to the
bot (click-fraud polling, binary-download retries, spam probes) was therefore
handed to the model as an example of ordinary human browsing.

Counted from the ground-truth files themselves, not estimated:

| source | confirmed C&C (port 80) | bot traffic labelled benign |
|---|---:|---:|
| CTU-13 s1 | 274 flows | 969 flows |
| CTU-13 s2 | 632 | 9,882 |
| CTU-13 s5 | 18 | 114 |
| CTU-13 s7 | 26 | 15 |
| CTU-13 s9 | 2,551 | 9,446 |
| CTU-13 s13 | 456 | 1,717 |
| **CTU-13 total** | **3,957** | **22,143** (5.6×) |
| Botnet-25-1 (ZeusV1) | 11,228 rows | 28,681 rows |
| Botnet-78-1/2 (Zeus78) | 0 | 371,151 rows |

**273,944 requests across 6,143 windows.** Three malware captures turned out to
contain no clean browsing at all:

| capture | "benign" windows before | after | withdrawn |
|---|---:|---:|---:|
| zeus-25-1 | 1,065 | **1** | 99.9% |
| zeus-26 | 16 | **0** | 100% |
| zeus-78-1 | 2,819 | **0** | 100% |
| zeus-78-2 | 1,221 | **0** | 100% |
| ctu13-s9 | 14,341 | 13,573 | 5% |
| ctu13-s1/s2/s5/s13 | 36,506 | 36,251 | <1% each |

That traffic is periodic, referrer-less and single-endpoint: the exact shape
this detector exists to find. Scoring it as a false positive measured how
incomplete the capture's labelling is, not how often the detector is wrong. It
is equally unsafe to call it *positive*: the ground truth never confirmed a C&C
channel. So it is dropped as **undetermined**, the same treatment a window
already received for straddling the C&C boundary, and recorded in the new
`botnet_noncc_ratio` column.

**This removes negatives only.** The positive class did not move by one window:
6,890 before and after, exact per-family match (verified).

### What it was worth, measured

Holding the model configuration completely fixed and swapping only the corpus,
same folds, same threshold rule:

| | LOFO acc | precision | recall | F1 | ROC-AUC |
|---|---:|---:|---:|---:|---:|
| old config × old corpus | 0.7784 | 0.8071 | 0.8105 | 0.7872 | 0.9134 |
| old config × corrected corpus | 0.8654 | 0.8185 | 0.9444 | **0.8761** | 0.9571 |

**+0.089 F1 and +0.044 AUC from the data correction alone.** Per-fold ROC-AUC
moved ZeusV1 0.857 → 0.997, Neris 0.958 → 0.992. The detector was never as weak
as the old numbers said.

### No more real C2 exists to add

Checked before concluding the corpus was fixed in size. The unused CTU-13
scenarios (3, 4, 6, 8, 10, 11, 12) contain **zero** port-80 `-CC` flows; their
C&C is IRC or a custom port, which an HTTP beacon detector is not scoped to. The
unused Stratosphere captures (4, 8, 13, 3, 127-2, 194-1, 344-1) carry no `-CC`
ground truth at all. **310 in-scope C2 windows is the ceiling of the real data on
disk**, and no synthetic traffic was added to raise it.

---

## 2. The scope rule admitted channels nobody ever answered

Scope was `error_status_ratio < 1.0`, meant to read "the channel completed at
least one exchange". But `window_features()` sets `error_status_ratio` to 0.0
when **no** response status was seen at all, so a channel nobody ever answered
scored identically to a perfectly healthy one.

Measured: 20 Neris windows to `195.190.13.70/78` carry status `-` and
`response_body_len` 0 on all 445 of their requests. The server never replied.
They were in scope only because the error ratio defaulted to zero.

Adding `status_known_ratio > 0` applies the criterion's own stated intent, and
treats these the way Zeus78's all-403 dead channel is already treated. Exactly
20 windows move, all Neris; nothing else is touched.

In scope after both corrections: **310 C2 windows across 40 C&C pairs**, against
52,599 benign windows.

---

## 3. Results

Operating point: a **5% false-positive budget**. Plain accuracy is only quoted on
a class-balanced held-out set, averaged over 5 negative draws.

### Unseen malware family (LOFO): the headline

The family *and every capture it appears in* are absent from training.

| held-out family | C2 windows | accuracy | precision | recall | F1 | ROC-AUC |
|---|---:|---:|---:|---:|---:|---:|
| ZeusV1 | 226 | 0.9792 | 0.9601 | 1.0000 | 0.9796 | 0.9992 |
| Neris | 65 | 0.9585 | 0.9495 | 0.9692 | 0.9591 | 0.9916 |
| FastFlux | 12 | 0.8417 | 0.9236 | 0.7500 | 0.8267 | 0.9389 |
| *Sogou* | *3* | n/a | n/a | n/a | n/a | *excluded, <10 positives* |
| *ZeusB26* | *3* | n/a | n/a | n/a | n/a | *excluded, <10 positives* |
| *Zeus78* | *1* | n/a | n/a | n/a | n/a | *excluded, <10 positives* |
| **per-window average** | **303** | **0.9693** | **0.9564** | **0.9835** | **0.9697** | |
| per-family average | 3 folds | 0.9264 | 0.9444 | 0.9064 | 0.9218 | 0.9765 |
| *target* | | *0.94* | *0.95* | *0.97* | *0.95* | |

**Per-window: all four targets met.** Per-family: none of them.

Both are standard (micro- and macro-average) and both are honest. They differ
because the macro average lets FastFlux's **12** windows carry the same third of
the result as ZeusV1's **226**. Which to quote depends on the question:

* *"How well does it do on the windows it will actually see?"* → per-window.
* *"How well does it do on the next family, whichever that is?"* → per-family.

The per-family number is the conservative one and is the fair answer to a panel
asking about novel-threat generalisation. Neither is hidden here.

**FastFlux is the whole gap**, and the reason is structural, not a tuning
failure: it is a *fast-flux* botnet, so it rotates destination IPs by design,
while windows are cut per `(source, destination)` pair. Its 12 windows are
spread over 3 destinations with payloads from 9.7 bytes to 21.7 kB, and several
windows hold only 7 to 15 requests. Its ROC-AUC is still 0.939: the model ranks
its beacons well above benign; what suffers is where one shared threshold lands
for it. One window is worth 8.3 points of its recall.

### Unseen C&C server (LOPO)

Same family may be in training; the specific C&C server is not.

| | folds | accuracy | precision | recall | F1 | ROC-AUC |
|---|---:|---:|---:|---:|---:|---:|
| per-window average | 4 | 0.9715 | 0.9603 | 0.9837 | 0.9719 | |
| per-family average | 4 | 0.9565 | 0.9644 | 0.9500 | 0.9543 | 0.9988 |

**LOPO is the easier protocol and is not the headline.** It is also where the
old figure was inflated: 11 of its 15 C&C pairs contribute only 3 windows each,
and a 3-window fold scores 1.000 or 0.000 with nothing in between. Averaging
those in gives 0.9884 / 0.9905 / 0.9867 / 0.9878, reported here for
transparency and **not used**. The same ≥10-positive reliability rule LOFO
always applied is now applied to LOPO as well; previously it was applied to one
protocol and not the other.

### The absolute false-positive load, stated plainly

The balanced numbers above answer "when it sees one of each, how often is it
right". They do not answer "how much noise does it make". On the **full,
unbalanced** held-out data (49,922 benign windows against 303 C2), the same
operating point gives:

| | predicted benign | predicted beacon |
|---|---:|---:|
| **actually benign** | 47,351 | **2,571** (5.2%) |
| **actually C2** | 5 | 298 (98.3%) |

**2,571 benign windows cross the ML threshold.** That is the 5% budget doing
exactly what it was set to do, and it is why the ML score is not the verdict:
`risk_fusion.py` weights it 0.55 and a both-signal guard stops an ML score from
reaching BEACON without independent heuristic corroboration. Measured on a
realistic browsing window, the live engine returns **0.0008**; the bulk of that
5% sits just over the line, not near the top. Anyone quoting the balanced
precision without this table is quoting half the picture.

### Traffic outside the scope, reported rather than dropped

The 6,580 excluded windows (Zeus78's dead channel, Neris's unanswered one) are
still scored, against 2,902 benign windows held out of this model's training:
**ROC-AUC 0.9987, median score 0.713, 99.98% above threshold.** They are outside
the *defined scope* of "active periodic C&C", not outside the detector's reach.

---

### End to end, and the limit that is not the classifier's

Everything above measures the **classifier**. `eval_c3_real_world_pipeline.py`
measures what an analyst sees (the real `feature_engine → ml_classifier →
heuristic rules → risk_fusion` objects, nothing reimplemented) on every real C2
window of the held-out family, including the dead channels outside the training
scope. A capture carries no browser context, so three conditions are reported
and never blended: **A** = context-blind (interceptor.py's own "assume benign"
fallback, a genuine lower bound); **B** = background tab + idle user assumed;
**C** = foreground tab + idle user assumed (an in-page beacon). Benign windows
get the same assumed context, the worst case for false positives.

> **Scoring rework, 2026-09-14: the figures below replace the 2026-09-13
> ones.** Three problems were measured on real data before anything changed:
> 1. **The ML score's scale broke the fusion.** The model is uncalibrated and
>    calls C2 at a raw 0.137, but the fusion was built around a ~0.5 decision
>    point. Six saved windows of the project's own Real-World Beacon Test (raw
>    0.13 to 0.36, all at or above the threshold) fused to 0.34 to 0.47, so the
>    test could never be confirmed, and the dashboard showed "ML 21%" for traffic the
>    model had classified as C2. **Fix:** the ML score is shown and fused on the
>    model's *decision scale* (`ml_classifier.to_decision_scale`, a log-odds
>    shift: threshold → 0.50; order-preserving, so every ROC/PR figure above
>    stands).
> 2. **Supporting evidence alone corroborated a beacon.** "User idle" (+0.25)
>    plus a high ML score confirmed an ad-verification CDN with random timing
>    (`cdn.doubleverify.com`, iat_cv 3.36) as a BEACON on live browsing.
>    **Fix:** the heuristic now scores only when the timing has a beacon rhythm
>    (clockwork, or the new *steady rhythm despite jitter* rule), and a BEACON
>    also needs the ML score at or above its 50% line (`ML_CONFIRM_FLOOR`).
> 3. **Early readings disagreed by construction** ("ML 8%, heuristic 47%" on a
>    young beacon). **Fix:** ML, heuristic and fused score now share one
>    timing-maturity weight.
>
> Fusion weights (0.55 / 0.45) and verdict thresholds (0.30 / 0.52) are unchanged.

LOFO, end to end, held out (BEACON / SUSPICIOUS-or-above; FP = held-out real
browsing windows flagged BEACON):

| held-out family | **A**: SUSP+ | **B**: BEACON | **B**: SUSP+ | **B**: FP | **C**: BEACON | **C**: SUSP+ | fused ROC-AUC (B) |
|---|---:|---:|---:|---:|---:|---:|---:|
| ZeusV1 (periodic) | 1.0000 | **1.0000** | 1.0000 | 0.0000 | **1.0000** | 1.0000 | 1.0000 |
| Neris | 0.7579 | 0.0842 | 0.9053 | 0.0000 | 0.0842 | 0.9684 | 0.9927 |
| FastFlux | 0.7500 | 0.0000 | 0.7500 | 0.0000 | 0.0000 | 0.7500 | 0.9591 |
| Zeus78 | 0.9363 | 0.0000 | 0.9363 | 0.0010 | 0.0000 | 0.9363 | 0.9934 |

Under condition A no window reaches BEACON (by design) and no benign window is
flagged BEACON. Against the 2026-09-13 run: SUSPICIOUS-or-above rose for every
family (A: Neris 0.49 → 0.76, FastFlux 0.42 → 0.75, Zeus78 0.37 → 0.94); BEACON
rose for ZeusV1 (0.965 → 1.0) and fell for Neris (0.274 → 0.084), FastFlux
(0.083 → 0) and Zeus78 (0.045 → 0).

**Why those three fall, and why that is the intended reading.** A BEACON verdict
now states two things: the model calls the traffic C2, *and* the timing has a
beacon rhythm. FastFlux, Zeus78 and most Neris windows have no rhythm (median
timing CV 0.91 / 1.61 / 0.73, against 0.003 for ZeusV1 and 1.82 for real human
browsing), so they are surfaced as SUSPICIOUS. The old BEACONs for them came
from "high ML + assumed background tab", the same path that produced the live
false BEACON on the ad CDN.

**The cost, stated plainly.** On *held-out capture-background* windows (lab
machines' own automated HTTP, not browser traffic), with the worst-case
context assumed, the BEACON rate rose from 0.64% to 1.36%. Inspected, those
windows are software heartbeats: one endpoint, GET, replies of 0 to 7 bytes,
no Referer, every 3 to 12 s. Their ML (raw 0.15 to 0.28) and heuristic (0.55 to
0.73) overlap the real Real-World Beacon Test's (raw 0.13 to 0.36, heuristic 0.60)
almost exactly, so **no fusion setting separates them**: the previous design
avoided them only by also failing to confirm the real test beacon. On held-out
real human browsing the BEACON rate fell (0.08% → 0.03% pooled).

**Real live windows, current code:** all 4 saved windows of the local test
beacon and 4 of 6 windows of the Real-World Beacon Test are BEACON (the other two
are an early window and one at ML 0.485, just under the line; the host is
confirmed); the 5 ad-tech hosts from the 60-minute browsing run are SAFE or
SUSPICIOUS, none BEACON. A later re-score of all 46 windows saved by the five
live Real-World Beacon Test runs since 2026-09-08 gives 38 BEACON and 8
SUSPICIOUS (still maturing), with every run confirmed; see
`test/C3/TEST_CASE_03_Real_World_Reputation_Checked_C2_Beacon.md`.

**Known remaining gap.** The model's strongest input is a *missing* Referer
(malware processes never send one). A beacon written as an ordinary in-page
`fetch()` sends one, and the model then scores it low (the real test beacon:
raw 0.233 without a Referer, 0.009 with one). The heuristic still flags the
rhythm, so the host reads SUSPICIOUS, not BEACON. Closing that needs a model
that does not lean on the Referer: a retrain, not a fusion change.

So: *the classifier generalises to unseen families; the end-to-end BEACON
verdict confirms periodic beacons where browser context is available, and
reports non-periodic C2 as SUSPICIOUS.* Quoting either number as the other is
wrong.

---

## 4. What changed in the model, and why each change was measured

Every one of these was compared against its alternatives on LOFO (the protocol
the headline is read from), and the loser dropped.

| change | alternative | evidence |
|---|---|---|
| **No probability calibration** | isotonic (previous), sigmoid | LOFO mean ROC-AUC 0.9780 uncalibrated, 0.9571 isotonic, 0.9440 sigmoid. At ~300 positives the isotonic fit is a coarse step function whose ties collapse ranking resolution exactly where the decision is made. |
| **Threshold by false-positive budget** | F1-optimal threshold | An F1-optimal cut is positioned by where the *positives* sit, and every fold holds out a family with its own score distribution. The negative side is the same population every time. |
| **5% budget** | 1% to 8% swept | 1% → recall 0.611; 3% → 0.886; **5% → 0.924**; 8% → 0.957 but precision 0.914. 5% is the F1 peak, on the recall-leaning side. |
| **Full domain priors + upload prior** | minimal priors | §5: this one cost corpus accuracy and was kept anyway. |
| **Equal-family weighting** | sqrt, capped, flat | LOFO F1 0.9040 equal vs 0.8713 sqrt, 0.8712 capped. |
| **XGBoost alone** | logistic regression, XGB+LR blend | mean LOFO AUC: XGB 0.9774, blend 0.9670, logistic regression 0.8754 to 0.9090. |
| **All 20 features kept** | greedy backward elimination | Elimination reached +0.003 AUC by dropping timing features. **Not taken**: with three reliable folds, selecting features against the same folds the headline is read from tunes the headline to its own test set. Measured, recorded, left on the table. |

Top gain-based importances: `referrer_absent_ratio` 0.285, `path_only_entropy`
0.143, `payload_repeat_ratio` 0.115, `iat_spread_ratio` 0.072. Leave-one-out
agrees on the top feature: removing `referrer_absent_ratio` costs 0.0394 mean
AUC, against 0.0171 for the next most costly (`upload_download_ratio`) and
0.0144 for `payload_cv`. Six features *gain* a little AUC when removed, all of
them timing-shape measures; that is the same result as the per-family medians
(only ZeusV1 is metronomic) arriving by a different route, and it is why the
timing priors matter more than the timing features do.

---

## 5. One change that cost accuracy and was made anyway

Relaxing the timing monotone constraints raised corpus accuracy. It also broke
the detector on an idealised beacon.

A perfectly regular beacon (`iat_cv` 0, `payload_cv` 0, `url_path_entropy` 0)
sits in a corner of feature space **no training window occupies**, because real
captures always carry some jitter. An unconstrained tree is free to do anything
there, and measured, it put a textbook GET-only beacon at **0.081**, below its
own threshold, while the browser-side heuristic was flagging the same window
five different ways. `test_a_persistent_beacon_is_still_confirmed` caught it.

| priors kept | LOFO per-window F1 | idealised GET beacon | realistic browsing |
|---|---:|---:|---:|
| minimal (3) | 0.9735 | **0.081** ✗ | 0.0005 |
| full | 0.9631 | 0.379 | 0.0011 |
| **full + upload prior** | **0.9697** | **0.425** ✓ | 0.0008 |

Restored, plus `upload_download_ratio: +1` (more upload relative to download is
more C&C-like, never less). Cost: 0.004 per-window F1. Bought: correct behaviour
where the corpus has no data, which is the entire reason domain priors exist.
Fused verdict 0.55×0.425 + 0.45×0.73 = 0.562 ≥ 0.52 → BEACON.

**A note on a wrong turn, kept here deliberately.** The first diagnosis of that
failure blamed `upload_download_ratio`, because the missed beacon had it at 0
and 88% of benign windows do too. Checking instead of assuming showed the
opposite: real zero-upload C2 windows are detected **100%** (FastFlux 10/10,
Neris 48/48, Sogou 3/3, mean score 0.978), and removing the feature collapsed
ZeusV1 recall to 0.500. The real cause was the missing priors.

---

## 6. Deployment

`models/c3_beacon_classifier.pkl`, wired in `core/c3/ml_classifier.py`.
Same 20 features and the same `{model, feature_names, threshold}` payload, so
nothing in `feature_engine.py` or the fusion layer needed changing. It is a bare
`XGBClassifier` rather than a `CalibratedClassifierCV` wrapping five of them, so
the artefact is 298 kB instead of 2.1 MB and loads correspondingly faster.

### 6.1 Why the file is smaller than C1's and C2's models, checked rather than assumed

C1's and C2's models are also XGBoost, and both are close to 2 MB: `bitb_classifier.pkl`
and `url_classifier.pkl` use 489 trees at depth 7. C3's is 300 trees at depth 4.
That difference alone (roughly 8x the leaf capacity per tree, times 1.6x the tree
count) accounts for the size gap; nothing is missing from the C3 file, and its
payload already carries feature importances, LOFO/LOPO summaries and provenance
alongside the model.

The question worth asking is not "why is it smaller" but "would it detect
better if it were bigger", so `scripts/sweep_c3_model_capacity.py` retrained
the SAME LOFO/LOPO protocol at seven capacities, from a modest increase up to
literally C1/C2's own tree depth and count. Size grows as expected; accuracy
does not follow it, on any of the seven:

| config | size | LOFO F1 | LOFO AUC | LOPO F1 |
|---|---:|---:|---:|---:|
| **deployed: 300 trees, depth 4** | **296 KB** | **0.9218** | 0.9765 | **0.9543** |
| 500 trees, depth 4 | 486 KB | 0.9189 | 0.9787 | 0.9540 |
| 800 trees, depth 4 | 754 KB | 0.9005 | 0.9755 | 0.9543 |
| 300 trees, depth 6 | 285 KB | 0.8926 | 0.9753 | 0.9383 |
| 500 trees, depth 6 | 466 KB | 0.8963 | 0.9787 | 0.9387 |
| 300 trees, depth 7 | 281 KB | 0.8839 | 0.9758 | 0.9374 |
| C1/C2's own capacity (489 trees, depth 7) | 432 KB | 0.8680 | 0.9758 | 0.9399 |

Every larger configuration measures at or below the deployed model's LOFO F1,
and the loss grows with the capacity added; matching C1/C2's own tree depth
and count costs 5.4 points of LOFO F1 and 1.4 of LOPO F1. The AUC barely moves
either way, so this is not the model getting worse at ranking; it is the
5%-budget threshold landing on a worse point because the extra capacity
memorises the families already in training rather than generalising to the
one held out, which is exactly what LOFO exists to catch. The loss concentrates
on FastFlux, the family with the fewest windows (12): its LOFO F1 falls from
0.827 at the deployed size to 0.709 at C1/C2's capacity, more than three times
the drop seen on ZeusV1 (226 windows). This is consistent with the rest of
this document: C1's and C2's classifiers are trained on far more labelled
examples than C3's 310 in-scope real C2 windows, so more capacity helps there
and hurts here. Full breakdown, including every held-out family:
`data/_c3_capacity_sweep.json`. **Conclusion: the deployed model's size is a
correct consequence of how little real, labelled C2 traffic exists, not a
defect, and it was left unchanged.**

`models/*.pkl` is gitignored (existing project convention), so the artefact
itself is not committed; `python scripts/train_c3_final_model.py` rebuilds it
byte-for-byte from the tracked corpus. Every seed is fixed; the run was executed
three times during this work and reproduced identical fold metrics each time.

| check | result |
|---|---|
| `test_c3_units.py` | **144/144 pass** (2026-09-14) |
| `test_c3_feature_parity.py` | **4/4 pass**: train/serve agree to 1e-6 |
| real Zeus C2 window, live engine | scores **0.9481** |
| realistic browsing window, live engine | scores **0.0008** |
| C1 / C2 / C4 | untouched (see below) |

Exactly two existing files were edited for this work:
`scripts/build_c3_18feat_dataset.py` (the labelling rule, §1 and §2) and
`core/c3/ml_classifier.py` (the model path). Everything else added is new:
`scripts/train_c3_final_model.py`, `scripts/make_c3_model_charts.py`, this
document, `data/_c3_final_model_results.json`, `paper/figures/model/`, and the
rebuilt `data/c3_18feat_dataset.csv` + `data/_c3_18feat_build_stats.csv`.
No file belonging to C1, C2 or C4, and none of the files they share with C3
(`core/main.py`, `core/playwright_session.py`, `frontend/dashboard.html`), was
opened for writing for the model work. No test was modified to make
it pass; the one test that failed mid-way (§5) was fixed in the model, not in
the test.

**Rollback:** the previous model, `models/c3_xgb_scoped_calibrated_20260911.pkl`,
was moved out of the repository on 2026-09-14 (archive folder
`L A S T - Removals\2026-09-14_final_clean\models\`). Restore it from there and
point `_model_path` at it. That model is isotonic-calibrated, so its score scale
differs: re-check `risk_fusion.py`'s weights with
`scripts/tune_c3_fusion_weights.py` if you do.

---

## 7. What is still true and limiting

1. **310 positive windows, 6 families, 3 of them with under 5 windows.** This is
   all the real labelled HTTP C&C on disk (§1). Three LOFO folds carry the
   headline.
2. **FastFlux is under-served by per-destination windowing** (§3). A fast-flux
   family fragments across rotating destinations.
3. **Sogou cannot be detected and is not claimed to be**: 3 windows, and on the
   strongest feature it looks like browsing (`referrer_absent_ratio` 0.06 against
   1.00 for every other family). It is excluded from the mean by the
   pre-declared <10-positive rule, and reported as 0.000 rather than hidden.
4. **The corpus is 2011 to 2014 traffic.** Modern C&C over HTTPS to cloud fronts
   (Discord, Slack, cloud APIs) is not represented. `the 2026-09-11 hardening pass`
   Section 4 covers this.
5. **LOPO's 11 three-window folds** remain in the JSON, flagged unreliable.
