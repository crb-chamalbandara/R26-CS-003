"""
Build a REAL-HTTP-PAYLOAD C2 training dataset from CTU-13's Zeek http.log files.

WHY THIS EXISTS
---------------
The previous datasets (data/c3_ctu13_c2_dataset.csv, c3_xgb_training.csv) took
payload_size_mean/std from Argus `TotBytes` -- whole-flow byte totals ranging up
to 2.1 GB. The live system's feature_engine.py takes the same feature from CDP's
encodedDataLength, i.e. the bytes of a single HTTP response (typically hundreds).
That ~1000x scale mismatch was measured to break the model outright: holding a
textbook beacon's timing fixed and sweeping payload alone,

    payload_size_mean=50   -> ML score 0.5744
    payload_size_mean=92   -> ML score 0.0000   <- learned cliff
    payload_size_mean=512  -> ML score 0.0000   <- where every real beacon lands

so the deployed model scored ~0 on all real browser traffic regardless of timing.

Stratosphere publishes a Zeek http.log alongside every CTU-13 scenario, carrying
`request_body_len` / `response_body_len` -- REAL per-transaction HTTP payload
bytes, the same quantity feature_engine.py measures. This script builds the
training set from those logs instead, so training and serving finally measure
the same thing.

SOURCE + PROVENANCE
-------------------
  http.log : https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-<NN>/bro/http.log
  labels   : the local .binetflow files' "-CC<n>-" command-and-control marker
             (the same ground truth every prior C3 dataset used -- unchanged)

Scenario <-> Botnet-NN mapping was verified against each capture's official
README, not assumed:
    scenario 1 = Botnet-42   scenario 2 = Botnet-43   scenario 5  = Botnet-46
    scenario 7 = Botnet-48   scenario 9 = Botnet-50   scenario 13 = Botnet-54

Only these six scenarios are used, because they are the only ones whose C2
channel is actually HTTP. Measured C2-flow destination ports across all 13:
    scenarios 1,2,5,7,9,13 -> port 80 dominant (3,957 of 6,021 C2 flows = 65.7%)
    scenarios 3,4,6,8,10,11,12 -> C2 on 1027 / 5678 / 3389 / 6667(IRC) / custom
An IRC or RDP C2 channel produces no rows in http.log at all, so including those
scenarios would contribute benign traffic labeled as if it were C2-capable. They
are excluded deliberately and the exclusion is reported, not hidden.

LABELLING
---------
label_c2 = 1 when an http.log row's (src_ip, src_port, dst_ip, dst_port) matches
a binetflow flow carrying the "-CC<n>-" marker. Verified on scenario 1: all 279
http.log rows on C2 host-pairs matched a C2 4-tuple, zero unmatched -- so
4-tuple and host-pair labelling agree exactly and the labels are unambiguous.
(The binetflow's 45 non-C2 flows on those same pairs generated no HTTP
transaction at all -- connection attempts, not requests.)

FEATURES
--------
Computed with the EXACT helper functions imported from core/c3/feature_engine.py
(never reimplemented), so training and serving cannot drift:

  iat_mean_ms, iat_cv, iat_bowley_skewness, iat_mad_ms  -- timing, from http `ts`
  payload_size_mean, payload_size_std   -- from `response_body_len`
  request_burst_count                   -- _burst_count() over timestamps
  http_post_ratio                       -- from `method`   (NEW: NetFlow lacked this)
  url_path_entropy                      -- from `uri`      (NEW: NetFlow lacked this)

payload note, stated honestly: live `size_bytes` prefers CDP encodedDataLength
(response bytes on the wire, INCLUDING headers) and falls back to Content-Length
(the response BODY length, which is exactly response_body_len). So
response_body_len is an exact match for the fallback and a close proxy for the
primary, differing by per-response header bytes. That residual difference is
small and constant-ish; it is not corrected here, because inventing a header
size would be fabricating data.

The 6 browser-context features (idle time, tab state, initiator, same-site)
remain absent -- no network capture can contain them. They stay heuristic-only
in analyzer.py, exactly as the two-layer architecture intends.

OUTPUT
------
data/c3_ctu13_http_c2_dataset.csv  -- one row per (src,dst) window of <=50 requests
data/_ctu13_http_build_stats.csv   -- per-scenario accounting

Writes nothing else. Does not touch any model, existing dataset, or core/ module.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "core"))
from c3.feature_engine import (  # noqa: E402
    _bowley_skewness,
    _burst_count,
    _median_absolute_deviation,
    _path_diversity_entropy,
)

CTU13_ROOT = Path(r"D:\CTU-13-Dataset")
HTTP_ROOT = Path(r"D:\CTU-13-HTTP")
OUT_DATASET = REPO_ROOT / "data" / "c3_ctu13_http_c2_dataset.csv"
OUT_STATS = REPO_ROOT / "data" / "_ctu13_http_build_stats.csv"

WINDOW_SIZE = 50  # matches core/c3/interceptor.py deque(maxlen=50)

# Verified against each capture's official README (see module docstring).
SCENARIOS = {1: 42, 2: 43, 5: 46, 7: 48, 9: 50, 13: 54}

ZEEK_HTTP_COLS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "trans_depth",
    "method", "host", "uri", "referrer", "user_agent", "request_body_len",
    "response_body_len", "status_code", "status_msg", "info_code", "info_msg",
    "filename", "tags", "username", "password", "proxied", "orig_fuids",
    "orig_mime_types", "resp_fuids", "resp_mime_types",
]


def load_c2_tuples(scenario: int) -> tuple[set, set, int]:
    """Return (c2_4tuples, c2_host_pairs, n_http_c2_flows) from the binetflow."""
    matches = list((CTU13_ROOT / str(scenario)).glob("*.binetflow"))
    if len(matches) != 1:
        raise RuntimeError(f"expected 1 .binetflow for scenario {scenario}, found {len(matches)}")
    bf = pd.read_csv(matches[0], usecols=["SrcAddr", "Sport", "DstAddr", "Dport", "Label"],
                     dtype=str)
    is_cc = bf["Label"].str.contains(r"-CC\d", regex=True, na=False)
    cc = bf[is_cc]
    # http.log only ever contains HTTP, so restrict the label set to HTTP flows.
    cc_http = cc[cc["Dport"] == "80"]
    four = set(zip(cc_http.SrcAddr, cc_http.Sport, cc_http.DstAddr, cc_http.Dport))
    pairs = set(zip(cc_http.SrcAddr, cc_http.DstAddr))
    return four, pairs, len(cc_http)


def load_http_log(scenario: int) -> tuple[pd.DataFrame, int]:
    path = HTTP_ROOT / f"scenario_{scenario}_http.log"
    df = pd.read_csv(path, sep="\t", comment="#", names=ZEEK_HTTP_COLS, dtype=str,
                     on_bad_lines="skip", low_memory=False)
    raw = len(df)

    df["ts_f"] = pd.to_numeric(df["ts"], errors="coerce")
    df = df.dropna(subset=["ts_f"])

    # Zeek writes "-" for unset numeric fields; treat as 0 rather than dropping the
    # row, since a 0-byte response is a real and meaningful beacon observation.
    for col in ("request_body_len", "response_body_len"):
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

    df = df[df["id.orig_h"].notna() & df["id.resp_h"].notna()]
    df["method"] = df["method"].fillna("GET").str.upper()
    df["uri"] = df["uri"].fillna("/")
    return df, raw


def window_features(sub: pd.DataFrame) -> dict:
    n = len(sub)
    ts = sub["ts_f"].to_numpy(dtype=float)
    payload = sub["response_body_len"].to_numpy(dtype=float)

    if n == 1:
        iat_mean_ms = iat_cv = iat_bowley = iat_mad = 0.0
        burst = 0
    else:
        iats = np.diff(ts) * 1000.0
        iats = iats[iats >= 0.0]
        lst = iats.tolist()
        mean = float(np.mean(lst)) if lst else 0.0
        std = float(np.std(lst, ddof=0)) if len(lst) > 1 else 0.0
        iat_mean_ms = round(mean, 4)
        iat_cv = round(std / mean, 6) if mean > 0 else 0.0
        iat_bowley = round(_bowley_skewness(lst), 6)
        iat_mad = round(_median_absolute_deviation(lst), 4)
        burst = _burst_count(ts.tolist())

    methods = sub["method"].tolist()
    return {
        "iat_mean_ms": iat_mean_ms,
        "iat_cv": iat_cv,
        "iat_bowley_skewness": iat_bowley,
        "iat_mad_ms": iat_mad,
        "payload_size_mean": round(float(np.mean(payload)), 4),
        "payload_size_std": round(float(np.std(payload, ddof=0)), 4) if n > 1 else 0.0,
        "request_burst_count": int(burst),
        # Zeek's `uri` is already path+query, which is exactly what
        # feature_engine._path_for_entropy() produces from a full URL.
        "url_path_entropy": round(_path_diversity_entropy(sub["uri"].tolist()), 6),
        "http_post_ratio": round(sum(1 for m in methods if m == "POST") / n, 6),
        "n_flows": n,
        "window_start_ts": float(ts[0]),
    }


def process_scenario(scenario: int) -> tuple[pd.DataFrame, dict]:
    c2_four, c2_pairs, n_c2_flows = load_c2_tuples(scenario)
    df, raw_rows = load_http_log(scenario)

    four = list(zip(df["id.orig_h"], df["id.orig_p"], df["id.resp_h"], df["id.resp_p"]))
    df["is_c2"] = [t in c2_four for t in four]
    pair_hit = [(a, b) in c2_pairs for a, b in zip(df["id.orig_h"], df["id.resp_h"])]
    n_pair_rows = int(np.sum(pair_hit))
    n_c2_rows = int(df["is_c2"].sum())

    df = df.sort_values(["id.orig_h", "id.resp_h", "ts_f"], kind="mergesort").reset_index(drop=True)
    new_pair = (df["id.orig_h"] != df["id.orig_h"].shift()) | (df["id.resp_h"] != df["id.resp_h"].shift())
    pair_id = new_pair.cumsum().to_numpy()
    start_idx = np.zeros(len(df), dtype=np.int64)
    bidx = np.flatnonzero(new_pair.to_numpy())
    start_idx[bidx] = bidx
    start_idx = np.maximum.accumulate(start_idx)
    pos = np.arange(len(df), dtype=np.int64) - start_idx
    win_id = pair_id * 1_000_000 + (pos // WINDOW_SIZE)

    bounds = np.flatnonzero(np.diff(win_id) != 0) + 1
    starts = np.concatenate(([0], bounds))
    ends = np.concatenate((bounds, [len(df)]))

    src = df["id.orig_h"].to_numpy(dtype=object)
    dst = df["id.resp_h"].to_numpy(dtype=object)
    is_c2 = df["is_c2"].to_numpy(dtype=bool)

    rows = []
    for a, b in zip(starts.tolist(), ends.tolist()):
        feat = window_features(df.iloc[a:b])
        n_c2 = int(is_c2[a:b].sum())
        feat.update({
            "source_scenario": scenario,
            "src_host": src[a],
            "dst_host": dst[a],
            "n_c2_requests": n_c2,
            # ANY-based, matching build_ctu13_c2_dataset.py's documented rationale:
            # a beacon window often holds only 1-2 C2 requests among other traffic,
            # so a majority rule would erase nearly every positive.
            "label_c2": 1 if n_c2 > 0 else 0,
        })
        rows.append(feat)

    out = pd.DataFrame(rows)
    stats = {
        "scenario": scenario,
        "botnet_capture": f"Botnet-{SCENARIOS[scenario]}",
        "http_rows_raw": raw_rows,
        "http_rows_kept": len(df),
        "c2_http_flows_in_binetflow": n_c2_flows,
        "http_rows_labeled_c2": n_c2_rows,
        "http_rows_on_c2_host_pairs": n_pair_rows,
        "windows": len(out),
        "positive_windows": int(out["label_c2"].sum()) if len(out) else 0,
        "positive_windows_n_ge_4": int(out[out["n_flows"] >= 4]["label_c2"].sum()) if len(out) else 0,
    }
    return out, stats


def main():
    OUT_DATASET.parent.mkdir(parents=True, exist_ok=True)
    all_stats, first = [], True
    cols = ["source_scenario", "src_host", "dst_host", "window_start_ts",
            "iat_mean_ms", "iat_cv", "iat_bowley_skewness", "iat_mad_ms",
            "payload_size_mean", "payload_size_std", "request_burst_count",
            "url_path_entropy", "http_post_ratio",
            "n_flows", "n_c2_requests", "label_c2"]

    for scenario in SCENARIOS:
        print(f"[scenario {scenario:>2}] processing ...", flush=True)
        out, st = process_scenario(scenario)
        all_stats.append(st)
        print(f"[scenario {scenario:>2}] http_rows={st['http_rows_kept']:>7,} "
              f"windows={st['windows']:>6,} c2_rows={st['http_rows_labeled_c2']:>5} "
              f"pos_windows={st['positive_windows']:>4} "
              f"(n>=4: {st['positive_windows_n_ge_4']})", flush=True)
        out[cols].to_csv(OUT_DATASET, mode="w" if first else "a", header=first, index=False)
        first = False

    sdf = pd.DataFrame(all_stats)
    sdf.to_csv(OUT_STATS, index=False)
    print("\n=== DONE ===")
    print(sdf.to_string(index=False))
    print(f"\nsaved -> {OUT_DATASET}")
    print(f"saved -> {OUT_STATS}")


if __name__ == "__main__":
    main()
