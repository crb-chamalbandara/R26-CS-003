"""
Build the 18-FEATURE C3 dataset from REAL, LABELLED HTTP captures only.

WHY THIS EXISTS
---------------
The deployed model (models/c3_xgb_classifier.pkl) reads 6 features and was
trained on 110 positive windows. Both numbers are too small. This script keeps
the exact production windowing convention and adds 12 new features that are
computable BOTH from these capture logs AND live from what
core/c3/interceptor.py already records per request, so the model can actually
be deployed later without a train/serve mismatch.

NO SYNTHETIC DATA. Every row is a window of consecutive real HTTP requests
taken from a public capture, labelled by that capture's own ground truth.

SOURCES AND LABELS (all verified in this session, not assumed)
-------------------------------------------------------------
POSITIVES (real command-and-control channel traffic):
  1. CTU-13 scenarios 1, 2, 5, 7, 9, 13
     D:\\CTU-13-HTTP\\scenario_<n>_http.log  (Zeek)
     Ground truth: the matching D:\\CTU-13-Dataset\\<n>\\*.binetflow rows whose
     Label contains "-CC<digit>" and whose Dport is 80. A http.log row is C2
     when its (SrcAddr, Sport, DstAddr, Dport) 4-tuple is in that set.
     Families: Neris (1, 2, 9), unnamed fast-flux (5, 13), Sogou (7).
  2. Zeus V1  - CTU-Malware-Capture-Botnet-25-1 (Stratosphere weblog)
     Ground truth: per-request label containing "-CC<digit>-".
  3. Zeus B26 - CTU-Malware-Capture-Botnet-26 (Stratosphere weblog), same rule.
  4. Zeus 78  - CTU-Malware-Capture-Botnet-78-1 and 78-2 (Zeek http.log)
     Ground truth: the capture's own .binetflow.labeled marks 230,278 / 97,528
     flows "From-Botnet-TCP-HTTP-Zeus.CC.NonEncrypted-1", all of them the single
     pair 10.0.2.108 -> 81.88.48.95 on port 80. Verified in this session.
     DISCLOSURE: this C&C was already taken down when the capture was made, so
     97% of its replies are HTTP 403. The CLIENT behaviour is still genuine
     Zeus beaconing - two fixed endpoints /Zz/config.bin (GET) and /Zz/gate.php
     (POST), no referrer, ~4 s median interval - which is what the detector
     scores. To stop the model taking a shortcut on the error replies,
     error_status_ratio is computed for analysis but is NOT a model feature.

NEGATIVES (real benign browsing):
  5. Stratosphere CTU-Normal 14, 18, 20-33 (16 captures, Zeek http.log).
  6. Every non-C2 window inside the malware captures above. These are the
     infected host's ordinary browsing and background traffic. Labelling them
     negative is deliberate: the target is the C2 CHANNEL, not the host.

DELIBERATELY EXCLUDED
  - User-Agent features. The captures hold hundreds of user agents; a real
    browser only ever has one, so any model that learned on them would score
    zero in deployment.
  - Absolute request rate. Capture-clock dependent.

WINDOWING (identical to production, so the numbers stay comparable)
  Group by the (source IP, destination IP) pair, sort by timestamp, cut into
  CONSECUTIVE NON-OVERLAPPING blocks of at most 50 requests, keep blocks with
  at least 4 requests. Non-overlapping means no window shares a request with
  another, so a grouped train/test split cannot leak.
  50 matches core/c3/interceptor.py deque(maxlen=50); 4 is the point where all
  timing statistics are mathematically defined (3 gaps minimum for a quartile
  based skew).

LABEL RULE
  c2_ratio = share of C2 requests in the window.
    c2_ratio  > 0.5  -> label 1
    c2_ratio == 0.0  -> label 0
    anything between -> dropped as ambiguous (counted in the stats file)

OUTPUTS (all new files; nothing existing is read-modified or overwritten)
  data/c3_18feat_dataset.csv          features + label + group + family + meta
  data/_c3_18feat_build_stats.csv     per-capture accounting

Run:  python scripts/build_c3_18feat_dataset.py
Deterministic: stable sort, no randomness anywhere.
"""
from __future__ import annotations

import math
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent

CTU13_BINETFLOW_ROOT = Path(r"D:\CTU-13-Dataset")
CTU13_HTTP_ROOT = Path(r"D:\CTU-13-HTTP")
MALWARE_ROOT = Path(r"D:\CTU-Malware-Captures-HTTP")
NORMAL_ROOT = Path(r"D:\CTU-Normal-HTTP")

OUT_DATASET = REPO_ROOT / "data" / "c3_18feat_dataset.csv"
OUT_STATS = REPO_ROOT / "data" / "_c3_18feat_build_stats.csv"

WINDOW_SIZE = 50
MIN_FLOWS = 4

CTU13_SCENARIOS = [1, 2, 5, 7, 9, 13]
CTU13_FAMILY = {1: "Neris", 2: "Neris", 9: "Neris",
                5: "FastFlux", 13: "FastFlux", 7: "Sogou"}

ZEUS78_C2 = {("10.0.2.108", "81.88.48.95")}

NORMAL_CAPTURES = [14, 18, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33]

# The 18 features the model is allowed to read, in a fixed order.
MODEL_FEATURES = [
    # timing shape (8)
    "iat_cv", "iat_bowley_skewness", "iat_norm_mad", "iat_burstiness",
    "iat_autocorr_lag1", "iat_spread_ratio", "iat_clock_share", "iat_entropy_norm",
    # size (4)
    "payload_size_mean", "payload_cv", "payload_repeat_ratio", "upload_download_ratio",
    # url / http shape (5)
    "url_path_entropy", "unique_path_ratio", "http_post_ratio",
    "uri_len_norm", "uri_char_entropy_norm",
    # request behaviour (1)
    "referrer_absent_ratio",
]

# Computed and stored for analysis, NEVER given to the model.
DIAGNOSTIC_COLUMNS = ["error_status_ratio", "status_known_ratio", "n_flows",
                      "c2_ratio", "window_start_ts"]

_QUOTED = re.compile(r'"([^"]*)"')

_MISSING = {"-", "", "(empty)", "nan", "None", "none", "-\"", '"-"'}


# ---------------------------------------------------------------- maths ----
def _shannon_over_items(items) -> float:
    n = len(items)
    if n == 0:
        return 0.0
    total = 0.0
    for count in Counter(items).values():
        p = count / n
        total -= p * math.log2(p)
    return float(total)


def _char_entropy(text: str) -> float:
    return _shannon_over_items(list(text)) if text else 0.0


def _bowley_skewness(values: np.ndarray) -> float:
    """Quartile-based skew. Robust to outliers, unlike the moment version."""
    if len(values) < 3:
        return 0.0
    q1, q2, q3 = np.percentile(values, [25, 50, 75])
    denom = q3 - q1
    if denom == 0:
        return 0.0
    return float((q3 + q1 - 2 * q2) / denom)


# ------------------------------------------------------------- features ----
def window_features(ts: np.ndarray, resp: np.ndarray, req: np.ndarray,
                    methods: list, uris: list, referrers: list,
                    statuses: list) -> dict:
    """The 18 model features plus diagnostics, from one window of requests."""
    n = len(ts)

    # ---- Group A: timing shape (from timestamps only) --------------------
    gaps = np.diff(ts)
    gaps = gaps[gaps >= 0.0] * 1000.0          # milliseconds
    have = len(gaps) > 0

    g_mean = float(np.mean(gaps)) if have else 0.0
    g_std = float(np.std(gaps)) if len(gaps) > 1 else 0.0
    g_median = float(np.median(gaps)) if have else 0.0
    g_mad = float(np.median(np.abs(gaps - g_median))) if have else 0.0

    iat_cv = g_std / g_mean if g_mean > 0 else 0.0
    iat_norm_mad = g_mad / g_median if g_median > 0 else 0.0
    iat_burstiness = ((g_std - g_mean) / (g_std + g_mean)) if (g_std + g_mean) > 0 else 0.0

    if len(gaps) >= 3:
        a, b = gaps[:-1], gaps[1:]
        sa, sb = float(np.std(a)), float(np.std(b))
        if sa > 0 and sb > 0:
            iat_autocorr = float(np.mean((a - a.mean()) * (b - b.mean())) / (sa * sb))
        else:
            iat_autocorr = 0.0
    else:
        iat_autocorr = 0.0
    iat_autocorr = max(-1.0, min(1.0, iat_autocorr))

    if have and g_median > 0:
        p10, p90 = np.percentile(gaps, [10, 90])
        iat_spread = float((p90 - p10) / g_median)
        iat_clock = float(np.mean(np.abs(gaps - g_median) <= 0.10 * g_median))
    else:
        iat_spread = 0.0
        iat_clock = 0.0

    if len(gaps) >= 2:
        positive = gaps[gaps > 0]
        if len(positive) >= 2:
            counts = np.histogram(np.log10(positive + 1.0), bins=10)[0]
            counts = counts[counts > 0]
            total = counts.sum()
            ent = float(-sum((c / total) * math.log2(c / total) for c in counts))
            iat_entropy = ent / math.log2(10)
        else:
            iat_entropy = 0.0
    else:
        iat_entropy = 0.0

    # ---- Group B: size ----------------------------------------------------
    p_mean = float(np.mean(resp)) if n else 0.0
    p_std = float(np.std(resp)) if n > 1 else 0.0
    payload_cv = p_std / p_mean if p_mean > 0 else 0.0
    payload_repeat = 1.0 - (len(set(resp.tolist())) / n) if n else 0.0
    up_down = float(np.mean(req)) / (1.0 + p_mean) if n else 0.0

    # ---- Group C: url and http shape --------------------------------------
    url_entropy = _shannon_over_items(uris)
    unique_path = len(set(uris)) / n if n else 0.0
    post_ratio = sum(1 for m in methods if m == "POST") / n if n else 0.0
    uri_len = min(float(np.mean([len(u) for u in uris])) / 200.0, 1.0) if n else 0.0
    uri_char_ent = min(float(np.mean([_char_entropy(u) for u in uris])) / 6.0, 1.0) if n else 0.0

    # ---- Group D: request behaviour ---------------------------------------
    ref_absent = sum(1 for r in referrers if r in _MISSING) / n if n else 0.0

    # ---- diagnostics (not model inputs) -----------------------------------
    known = [s for s in statuses if s not in _MISSING]
    status_known = len(known) / n if n else 0.0
    if known:
        bad = 0
        for s in known:
            try:
                bad += 0 if 200 <= int(float(s)) < 300 else 1
            except ValueError:
                bad += 1
        error_ratio = bad / len(known)
    else:
        error_ratio = 0.0

    return {
        "iat_cv": round(iat_cv, 6),
        "iat_bowley_skewness": round(_bowley_skewness(gaps), 6),
        "iat_norm_mad": round(iat_norm_mad, 6),
        "iat_burstiness": round(iat_burstiness, 6),
        "iat_autocorr_lag1": round(iat_autocorr, 6),
        "iat_spread_ratio": round(iat_spread, 6),
        "iat_clock_share": round(iat_clock, 6),
        "iat_entropy_norm": round(iat_entropy, 6),
        "payload_size_mean": round(p_mean, 4),
        "payload_cv": round(payload_cv, 6),
        "payload_repeat_ratio": round(payload_repeat, 6),
        "upload_download_ratio": round(up_down, 6),
        "url_path_entropy": round(url_entropy, 6),
        "unique_path_ratio": round(unique_path, 6),
        "http_post_ratio": round(post_ratio, 6),
        "uri_len_norm": round(uri_len, 6),
        "uri_char_entropy_norm": round(uri_char_ent, 6),
        "referrer_absent_ratio": round(ref_absent, 6),
        "error_status_ratio": round(error_ratio, 6),
        "status_known_ratio": round(status_known, 6),
        "n_flows": int(n),
        "window_start_ts": float(ts[0]),
    }


# -------------------------------------------------------------- parsers ----
def _zeek_fields(path: Path) -> list[str]:
    """Read the real #fields header. Field ORDER differs between captures
    (CTU-Normal-20 carries a `version` column that CTU-13 does not), so
    assuming a fixed column list silently shifts every value."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#fields"):
                return line.rstrip("\n").split("\t")[1:]
            if not line.startswith("#"):
                break
    raise ValueError(f"no #fields header in {path}")


def read_zeek_http(path: Path) -> pd.DataFrame:
    cols = _zeek_fields(path)
    df = pd.read_csv(path, sep="\t", comment="#", names=cols, dtype=str,
                     on_bad_lines="skip", low_memory=False)
    df["ts_f"] = pd.to_numeric(df["ts"], errors="coerce")
    df = df.dropna(subset=["ts_f"])
    df = df[df["id.orig_h"].notna() & df["id.resp_h"].notna()]
    out = pd.DataFrame({
        "ts": df["ts_f"].astype(float),
        "src": df["id.orig_h"].astype(str),
        "dst": df["id.resp_h"].astype(str),
        "sport": df.get("id.orig_p", pd.Series(["0"] * len(df), index=df.index)).astype(str),
        "dport": df.get("id.resp_p", pd.Series(["0"] * len(df), index=df.index)).astype(str),
        "method": df["method"].fillna("GET").astype(str).str.upper(),
        "uri": df["uri"].fillna("/").astype(str),
        "referrer": df["referrer"].fillna("-").astype(str),
        "status": df["status_code"].fillna("-").astype(str),
        "resp_bytes": pd.to_numeric(df["response_body_len"], errors="coerce").fillna(0.0),
        "req_bytes": pd.to_numeric(df["request_body_len"], errors="coerce").fillna(0.0),
    })
    return out.reset_index(drop=True)


def read_weblog(path: Path) -> pd.DataFrame:
    """Stratosphere pipe-separated weblog with a trailing ' | label' column.

    Header:
      timestamp|s-port|sc-http-status|sc-bytes|sc-header-bytes|c-port|cs-bytes|
      cs-header-bytes|cs-method|cs-url|x-elapsed-time|s-ip|c-ip|
      cs-mime-type|cs(Referer)|cs(User-Agent) | label

    Fields 0..12 are taken with a bounded split and the label is recovered with
    rsplit from the right.

    The tail (mime | referer | user-agent) CANNOT be split on '|': the separator
    is sometimes a space instead of a pipe, e.g.  "text/html" "-"|"Mozilla/4.0|
    (compatible; ...)"  - and the user-agent itself contains '|'. Splitting on
    '|' therefore reads the user agent as the referrer, which silently sets
    referrer_absent_ratio to 0 for every Zeus C2 row. The three tail values are
    always quoted, so they are recovered by matching quoted groups instead.
    """
    rows = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh):
            if line_no == 0 and line.lower().startswith("timestamp"):
                continue
            line = line.rstrip("\n")
            if not line.strip():
                continue
            parts = line.split("|", 13)
            if len(parts) < 14:
                continue
            rest = parts[13]
            label = rest.rsplit("|", 1)[-1].strip() if "|" in rest else ""
            front = rest.rsplit("|", 1)[0]
            quoted = _QUOTED.findall(front)
            referer = quoted[1].strip() if len(quoted) > 1 else "-"
            try:
                ts = float(parts[0])
            except ValueError:
                continue

            def _num(value):
                try:
                    return float(value)
                except ValueError:
                    return 0.0

            rows.append((ts, parts[12], parts[11], parts[5], parts[1],
                         (parts[8] or "GET").upper(), parts[9], referer or "-",
                         parts[2] or "-", _num(parts[3]), _num(parts[6]), label))
    df = pd.DataFrame(rows, columns=["ts", "src", "dst", "sport", "dport",
                                     "method", "url", "referrer", "status",
                                     "resp_bytes", "req_bytes", "label"])
    df["uri"] = [_uri_of(u) for u in df["url"]]
    return df.drop(columns=["url"])


def _uri_of(url: str) -> str:
    try:
        parsed = urlparse(url)
        value = parsed.path or "/"
        if parsed.query:
            value += "?" + parsed.query
        return value
    except Exception:
        return "/"


# ------------------------------------------------------------ windowing ----
def make_windows(df: pd.DataFrame, is_c2: np.ndarray, group: str,
                 family_c2: str) -> tuple[list[dict], dict]:
    """Consecutive, non-overlapping blocks of <= WINDOW_SIZE per (src,dst)."""
    if len(df) == 0:
        return [], {"windows": 0, "pos": 0, "neg": 0, "ambiguous": 0, "requests": 0}

    order = np.argsort(df["ts"].to_numpy(float), kind="stable")
    df = df.iloc[order].reset_index(drop=True)
    is_c2 = np.asarray(is_c2)[order]

    ts_all = df["ts"].to_numpy(float)
    resp_all = df["resp_bytes"].to_numpy(float)
    req_all = df["req_bytes"].to_numpy(float)
    method_all = df["method"].tolist()
    uri_all = df["uri"].tolist()
    ref_all = df["referrer"].tolist()
    st_all = df["status"].tolist()
    pair_all = (df["src"].astype(str) + "->" + df["dst"].astype(str)).to_numpy()

    out, ambiguous = [], 0
    for pair in pd.unique(pair_all):
        idx = np.flatnonzero(pair_all == pair)
        for start in range(0, len(idx), WINDOW_SIZE):
            block = idx[start:start + WINDOW_SIZE]
            if len(block) < MIN_FLOWS:
                continue
            c2_ratio = float(np.mean(is_c2[block]))
            if 0.0 < c2_ratio <= 0.5:
                ambiguous += 1
                continue
            label = 1 if c2_ratio > 0.5 else 0
            feats = window_features(
                ts_all[block], resp_all[block], req_all[block],
                [method_all[i] for i in block], [uri_all[i] for i in block],
                [ref_all[i] for i in block], [st_all[i] for i in block],
            )
            feats["c2_ratio"] = round(c2_ratio, 4)
            feats["label"] = label
            feats["group"] = group
            feats["family"] = family_c2 if label == 1 else "benign"
            feats["pair"] = str(pair)
            out.append(feats)

    stats = {
        "windows": len(out),
        "pos": sum(1 for r in out if r["label"] == 1),
        "neg": sum(1 for r in out if r["label"] == 0),
        "ambiguous": ambiguous,
        "requests": len(df),
    }
    return out, stats


# --------------------------------------------------------------- sources ---
def load_ctu13_c2_tuples(scenario: int) -> set:
    matches = list((CTU13_BINETFLOW_ROOT / str(scenario)).glob("*.binetflow"))
    if len(matches) != 1:
        raise RuntimeError(f"scenario {scenario}: expected 1 .binetflow, found {len(matches)}")
    bf = pd.read_csv(matches[0], usecols=["SrcAddr", "Sport", "DstAddr", "Dport", "Label"],
                     dtype=str, low_memory=False)
    cc = bf[bf["Label"].str.contains(r"-CC\d", regex=True, na=False)]
    cc = cc[cc["Dport"] == "80"]
    return set(zip(cc.SrcAddr, cc.Sport, cc.DstAddr, cc.Dport))


def build() -> None:
    all_rows, stats_rows = [], []

    # 1. CTU-13 --------------------------------------------------------------
    for scenario in CTU13_SCENARIOS:
        http_path = CTU13_HTTP_ROOT / f"scenario_{scenario}_http.log"
        if not http_path.exists():
            print(f"  ctu13-s{scenario}: MISSING {http_path}", flush=True)
            continue
        c2_tuples = load_ctu13_c2_tuples(scenario)
        df = read_zeek_http(http_path)
        keys = list(zip(df["src"], df["sport"], df["dst"], df["dport"]))
        is_c2 = np.array([k in c2_tuples for k in keys])
        group = f"ctu13-s{scenario}"
        rows, st = make_windows(df, is_c2, group, CTU13_FAMILY[scenario])
        all_rows.extend(rows)
        st.update(capture=group, source="CTU-13 Zeek http.log",
                  family=CTU13_FAMILY[scenario], c2_requests=int(is_c2.sum()))
        stats_rows.append(st)
        print(f"  {group}: {st['requests']:,} req, {st['pos']} pos / {st['neg']} neg windows", flush=True)

    # 2. Zeus weblogs --------------------------------------------------------
    for folder, group, family in [
        ("CTU-Malware-Capture-Botnet-25-1", "zeus-25-1", "ZeusV1"),
        ("CTU-Malware-Capture-Botnet-26", "zeus-26", "ZeusB26"),
    ]:
        matches = list((MALWARE_ROOT / folder).glob("*.labeled"))
        if not matches:
            print(f"  {group}: MISSING weblog", flush=True)
            continue
        df = read_weblog(matches[0])
        is_c2 = df["label"].str.contains(r"-CC\d", regex=True, na=False).to_numpy()
        df = df.drop(columns=["label"])
        rows, st = make_windows(df, is_c2, group, family)
        all_rows.extend(rows)
        st.update(capture=group, source="Stratosphere weblog", family=family,
                  c2_requests=int(is_c2.sum()))
        stats_rows.append(st)
        print(f"  {group}: {st['requests']:,} req, {st['pos']} pos / {st['neg']} neg windows", flush=True)

    # 3. Zeus 78 -------------------------------------------------------------
    for folder, group in [("CTU-Malware-Capture-Botnet-78-1", "zeus-78-1"),
                          ("CTU-Malware-Capture-Botnet-78-2", "zeus-78-2")]:
        path = MALWARE_ROOT / folder / "http.log"
        if not path.exists():
            print(f"  {group}: MISSING http.log", flush=True)
            continue
        df = read_zeek_http(path)
        is_c2 = np.array([(s, d) in ZEUS78_C2 for s, d in zip(df["src"], df["dst"])])
        rows, st = make_windows(df, is_c2, group, "Zeus78")
        all_rows.extend(rows)
        st.update(capture=group, source="Stratosphere Zeek http.log",
                  family="Zeus78", c2_requests=int(is_c2.sum()))
        stats_rows.append(st)
        print(f"  {group}: {st['requests']:,} req, {st['pos']} pos / {st['neg']} neg windows", flush=True)

    # 4. Benign CTU-Normal ---------------------------------------------------
    for number in NORMAL_CAPTURES:
        path = NORMAL_ROOT / f"CTU-Normal-{number}" / "http.log"
        if not path.exists():
            print(f"  normal-{number}: MISSING", flush=True)
            continue
        df = read_zeek_http(path)
        is_c2 = np.zeros(len(df), dtype=bool)
        group = f"normal-{number}"
        rows, st = make_windows(df, is_c2, group, "benign")
        all_rows.extend(rows)
        st.update(capture=group, source="CTU-Normal Zeek http.log",
                  family="benign", c2_requests=0)
        stats_rows.append(st)
        print(f"  {group}: {st['requests']:,} req, {st['neg']} benign windows", flush=True)

    if not all_rows:
        print("NO DATA BUILT - check the D: paths above.")
        sys.exit(1)

    out = pd.DataFrame(all_rows)
    ordered = MODEL_FEATURES + DIAGNOSTIC_COLUMNS + ["label", "group", "family", "pair"]
    out = out[ordered]
    OUT_DATASET.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(OUT_DATASET, index=False)
    pd.DataFrame(stats_rows).to_csv(OUT_STATS, index=False)

    print()
    print(f"WROTE {OUT_DATASET}  ({len(out):,} windows)")
    print(f"      positives {int(out['label'].sum()):,}   "
          f"negatives {int((out['label'] == 0).sum()):,}   "
          f"prevalence {out['label'].mean():.4f}")
    print()
    print("Positive windows per family:")
    print(out[out["label"] == 1]["family"].value_counts().to_string())
    print()
    print("Windows per group:")
    print(out.groupby("group")["label"].agg(["size", "sum"]).to_string())


if __name__ == "__main__":
    build()
