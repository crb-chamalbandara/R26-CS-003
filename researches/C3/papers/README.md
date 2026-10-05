# Reading list for C3

Ten papers behind the design of C3, the Browser Execution Aware C2 Beacon
Detector. They are grouped the way C3 is built: first the C2 detection work C3
inherits from, then the browser work that explains why C3 runs inside the
browser at all, then the model, then the evaluation rules C3 is measured by.

Every PDF here was downloaded from the publisher's or the authors' own open
access page (USENIX, NDSS, arXiv, or a university site). Nothing is behind a
paywall.

## C2 detection: the problem C3 inherits

| # | Paper | Why it matters to C3 |
|---|---|---|
| 01 | Gu et al., **BotMiner**, USENIX Security 2008 | The founding idea C3 rests on: a bot is given away by the *pattern across many requests*, not by any single one, and that pattern can be found without knowing the protocol. C3 applies the same reasoning per destination host. |
| 02 | Perdisci et al., **Behavioral clustering of HTTP-based malware**, NSDI 2010 | Shows that malware C2 over plain HTTP is separable by the *structure* of its request traces (paths, methods, sizes). C3's URL, method and payload features measure the same kinds of structure. |
| 03 | Bilge et al., **DISCLOSURE**, ACSAC 2012 | Finds C2 servers from flow records alone, at scale. It is the strongest version of the approach C3 deliberately does *not* take, and it documents exactly what flow-level visibility cannot recover: who inside the host sent the request. |
| 04 | Holz et al., **Measuring and detecting fast-flux service networks**, NDSS 2008 | Why C3 scores behaviour rather than addresses: C2 infrastructure rotates its addresses on purpose. This is also the reason the FastFlux family is the weakest fold in C3's evaluation, since its traffic splits across several destinations. |

## Browser execution context: why C3 lives in the browser

| # | Paper | Why it matters to C3 |
|---|---|---|
| 05 | Kapravelos et al., **Hulk**, USENIX Security 2014 | Elicits malicious behaviour from browser extensions by driving them. Establishes the extension as a real attacker-controlled execution environment, which is the threat C3 is pointed at. |
| 06 | Jagpal et al., **Three years fighting malicious extensions**, USENIX Security 2015 | Google's own measurement of extension abuse at store scale. The evidence that this threat class is large and persistent, not hypothetical. |
| 07 | Li et al., **JSgraph**, NDSS 2018 | The closest prior work to C3's method: it instruments Chromium itself to record in-browser execution. The difference is purpose. JSgraph reconstructs an attack afterwards for forensics; C3 uses the same class of runtime signal to decide *live* whether traffic is a beacon. |

## The model

| # | Paper | Why it matters to C3 |
|---|---|---|
| 08 | Chen and Guestrin, **XGBoost**, KDD 2016 | The algorithm C3 runs (`models/c3_beacon_classifier.pkl`). Also the source of the monotone constraints C3 uses to encode direction priors, such as "a lower timing variance may only read as more beacon-like". |

## How C3 is allowed to claim anything

| # | Paper | Why it matters to C3 |
|---|---|---|
| 09 | Sommer and Paxson, **Outside the closed world**, IEEE S&P 2010 | The standing warning that machine learning results in intrusion detection do not survive contact with real deployment. C3 answers it by holding out whole malware families and whole C2 servers instead of splitting at random. |
| 10 | Arp et al., **Dos and don'ts of machine learning in computer security**, USENIX Security 2022 | The checklist C3's evaluation was audited against. Sampling bias is the entry that found a real defect in C3's own corpus: 95% of positive windows came from a single communicating pair, which a random split would have hidden. |

## Not included, and why

Garcia et al., *An empirical comparison of botnet detection methods* (Computers
& Security, 2014) is the paper for the CTU-13 captures that most of C3's
training data comes from. It is published by Elsevier and the authors' own
Stratosphere Laboratory page links to the publisher rather than hosting a copy,
so there is no open access PDF to place here. The citation is:

> S. Garcia, M. Grill, J. Stiborek, and A. Zunino, "An empirical comparison of
> botnet detection methods," Computers & Security, vol. 45, pp. 100-123, 2014.
> doi:10.1016/j.cose.2014.05.011

The dataset itself, and how C3 relabelled and scoped it, is documented in
`../C3_Final_Model_Results.md` and `../C3_Training_Dataset_Feature_Dictionary.md`.
