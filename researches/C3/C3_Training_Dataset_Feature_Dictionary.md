# C3 Training Dataset: Feature Dictionary

Describes `data/c3_training_dataset_clear.csv`: the exact data the deployed C3
model (`models/c3_beacon_classifier.pkl`) was trained on.

| | |
|---|---|
| Rows | 52,909 windows: 310 C2, 52,599 benign |
| Columns | 24: the model's 20 input features, then `label`, `family`, `capture`, `connection` |
| Source | real HTTP traffic from public, labelled captures (CTU-13 and Stratosphere). No row is synthetic. |
| Verified | retraining from this CSV alone, with the deployed model's own settings, gives the same 300 trees, the same score on every row and the same decision threshold (checked 2026-09-15; `core/c3/C3_ML_Train.ipynb` Section 5 repeats the check every time it runs) |

One row is one **window**: up to 50 consecutive HTTP requests from one source
to one destination. The rows are in the order the model was trained on them.

## Columns 1 to 20: the model's input features

These are the only columns the model reads, in the order it reads them. Every
one is scale-free (a ratio, a share or a normalised entropy), so it means the
same thing in an older malware capture and a live browser session.

| # | Column | Group | What it measures |
|---:|---|---|---|
| 1 | `iat_cv` | timing | How much the gaps between requests vary (0 = perfectly regular) |
| 2 | `iat_bowley_skewness` | timing | Skew of the gaps, measured with quartiles so one long pause does not dominate |
| 3 | `iat_norm_mad` | timing | Typical deviation of the gaps, relative to the typical gap (small under jitter) |
| 4 | `iat_burstiness` | timing | Whether requests come in bursts or evenly spaced |
| 5 | `iat_autocorr_lag1` | timing | Whether one gap predicts the next |
| 6 | `iat_spread_ratio` | timing | Spread of the gaps relative to their centre |
| 7 | `iat_clock_share` | timing | Share of gaps close to the typical gap: how much of the traffic keeps time |
| 8 | `iat_entropy_norm` | timing | Variety of gap lengths (low = a few repeated gaps, as a timer produces) |
| 9 | `payload_size_mean` | payload | Average response size |
| 10 | `payload_cv` | payload | How much response sizes vary (beacon replies are near-identical) |
| 11 | `payload_repeat_ratio` | payload | Share of responses with the single most common size |
| 12 | `upload_download_ratio` | payload | Bytes sent divided by bytes received |
| 13 | `url_path_entropy` | URL and method | Variety of the full request paths (low = one endpoint called again and again) |
| 14 | `unique_path_ratio` | URL and method | Share of requests whose full path is unique |
| 15 | `http_post_ratio` | URL and method | Share of requests that use POST |
| 16 | `uri_len_norm` | URL and method | Length of the request path, normalised |
| 17 | `uri_char_entropy_norm` | URL and method | Character variety of the request path, normalised |
| 18 | `referrer_absent_ratio` | request headers | Share of requests with no Referer header (a timer sends none; a click does). The model's strongest feature. |
| 19 | `path_only_entropy` | endpoint | Variety of request paths with the query string removed (defeats cache-busting) |
| 20 | `unique_path_only_ratio` | endpoint | Share of unique paths with the query string removed |

## Columns 21 to 24: label and where the row comes from

These are not model inputs. They are needed to reproduce the training (equal
weight per malware family, and the benign weight split between human browsing
and lab background) and the evaluation folds.

| # | Column | Meaning |
|---:|---|---|
| 21 | `label` | 1 = C2 (the window contains a request the capture's own ground truth marks as command-and-control), 0 = benign |
| 22 | `family` | The malware family of a C2 window (ZeusV1, Neris, FastFlux, Sogou, ZeusB26, Zeus78), or `benign` |
| 23 | `capture` | The public capture the window came from. `ctu13-s*` are CTU-13 scenarios, `zeus-*` are Stratosphere Zeus captures, `normal-*` are CTU-Normal human-browsing captures |
| 24 | `connection` | Source and destination addresses of the window's requests |

## Which windows are included

* **C2:** only active command-and-control channels, meaning the server answered
  at least once and at least one answer succeeded.
* **All windows:** at most 150 windows per connection, so one busy connection
  cannot dominate.
* **Left out before this dataset was built:** traffic the captures attribute to
  the infected machine but not to its C2 channel (click-fraud polling, download
  retries). It is neither a confirmed beacon nor genuine benign traffic.

Three connections appear under two families (Neris and FastFlux): the CTU-13
scenarios reuse the same infected lab host and C2 server addresses. There are
40 distinct C2 connections in total.
