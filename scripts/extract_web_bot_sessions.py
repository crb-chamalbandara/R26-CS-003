"""
Extract per-session C3 features from web_bot_detection_dataset.

Reads (never modifies) the external dataset at:
    C:\\Users\\Lasith Krishan\\Desktop\\web_bot_detection_dataset\\

Writes:
    <repo>/data/c3_web_bot_sessions.csv

10 server-log-derivable features per session (label: 0=human, 1=bot).

The 4 browser-context features (avg_idle_time_ms, user_active_ratio,
background_tab_ratio, extension_origin_ratio) require live CDP instrumentation
and cannot be recovered from server-side access logs; they are excluded.

Labels come exclusively from the dataset's researcher-provided annotation files.
No synthetic data is generated or used.
"""
from __future__ import annotations

import csv
import math
import re
import statistics
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

REPO_ROOT    = Path(__file__).resolve().parent.parent
DATASET_ROOT = Path(r"C:\Users\Lasith Krishan\Desktop\web_bot_detection_dataset")
OUTPUT_CSV   = REPO_ROOT / "data" / "c3_web_bot_sessions.csv"

MIN_REQUESTS = 5  # minimum requests per session for reliable timing features

# Apache Combined Log + extra session_id field:
# IP IDENT [timestamp] "request" STATUS BYTES "referer" SESSION_ID "user_agent"
_LOG_RE = re.compile(
    r'^\S+ \S+ \[([^\]]+)\] "([^"]*)" \d+ (\S+) "[^"]*" (\S+) "[^"]*"'
)

FEATURE_COLS = [
    "iat_mean_ms", "iat_cv", "iat_bowley_skewness", "iat_mad_ms",
    "requests_per_hour", "payload_size_mean", "payload_size_std",
    "http_post_ratio", "url_path_entropy", "request_burst_count",
]

CSV_FIELDS = ["session_id", "phase", "label", "request_count", *FEATURE_COLS]

SEP = "=" * 64


# ── Log parsing ────────────────────────────────────────────────────────────────

def _parse_line(line: str) -> tuple[str, float, str, str, int] | None:
    """
    Parse one Apache-format log line.
    Returns (session_id, unix_ts, method, path, bytes) or None.
    Anonymous requests (session_id == "-") are discarded.
    """
    m = _LOG_RE.match(line)
    if not m:
        return None
    ts_str, request, bytes_str, session_id = m.groups()
    if session_id == "-":
        return None
    try:
        ts = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except ValueError:
        return None
    parts = request.split(None, 2)
    method = parts[0].upper() if parts else "GET"
    path   = parts[1] if len(parts) > 1 else "/"
    try:
        size = int(bytes_str)
    except ValueError:
        size = 0
    return session_id, ts, method, path, size


def collect_sessions(
    log_paths: list[Path],
    allowed: set[str] | None = None,
) -> dict[str, list[tuple[float, str, str, int]]]:
    """
    Parse log files; group requests by session_id.
    If `allowed` is provided, only accumulate matching session IDs.
    Each entry: (unix_ts, method, path, bytes).
    """
    groups: dict[str, list] = defaultdict(list)
    for log_path in log_paths:
        print(f"    Parsing {log_path.name} ...", flush=True)
        with open(log_path, encoding="utf-8", errors="replace") as f:
            for raw in f:
                parsed = _parse_line(raw)
                if parsed is None:
                    continue
                sid, ts, method, path, size = parsed
                if allowed is not None and sid not in allowed:
                    continue
                groups[sid].append((ts, method, path, size))
    return dict(groups)


# ── Annotation loading ─────────────────────────────────────────────────────────

def load_annotations(*paths: Path, strip_suffix: bool = False) -> dict[str, int]:
    """
    Load one or more annotation files into {session_id: label}.
    label: 0 = human, 1 = bot (advanced_bot or moderate_bot).
    strip_suffix=True: remove trailing _N from session IDs (Phase 2 windowed format).
    """
    labels: dict[str, int] = {}
    for ann_path in paths:
        with open(ann_path, encoding="utf-8", errors="replace") as f:
            for raw in f:
                parts = raw.strip().split()
                if len(parts) < 2:
                    continue
                sid, label_str = parts[0], parts[1]
                if strip_suffix:
                    sid = re.sub(r"_\d+$", "", sid)
                labels[sid] = 0 if label_str == "human" else 1
    return labels


# ── Feature computation ────────────────────────────────────────────────────────

def _percentile(vals: list[float], pct: float) -> float:
    if not vals:
        return 0.0
    if len(vals) == 1:
        return float(vals[0])
    pos = (len(vals) - 1) * pct / 100.0
    lo, hi = math.floor(pos), math.ceil(pos)
    if lo == hi:
        return float(vals[lo])
    w = pos - lo
    return float(vals[lo] * (1 - w) + vals[hi] * w)


def _bowley(vals: list[float]) -> float:
    if len(vals) < 3:
        return 0.0
    s = sorted(vals)
    q1 = _percentile(s, 25)
    q2 = _percentile(s, 50)
    q3 = _percentile(s, 75)
    d = q3 - q1
    return float((q3 + q1 - 2 * q2) / d) if d != 0 else 0.0


def _mad(vals: list[float]) -> float:
    if not vals:
        return 0.0
    med = statistics.median(vals)
    return float(statistics.median([abs(v - med) for v in vals]))


def _shannon_entropy(paths: list[str]) -> float:
    text = "".join(paths)
    if not text:
        return 0.0
    n = len(text)
    counts: dict[str, int] = {}
    for c in text:
        counts[c] = counts.get(c, 0) + 1
    return float(-sum((cnt / n) * math.log2(cnt / n) for cnt in counts.values()))


def _burst_count(timestamps: list[float]) -> int:
    ts = sorted(timestamps)
    count, i = 0, 0
    while i <= len(ts) - 3:
        if ts[i + 2] - ts[i] <= 2.0:
            count += 1
            j = i + 3
            while j < len(ts) and ts[j] - ts[i] <= 2.0:
                j += 1
            i = j
        else:
            i += 1
    return count


def compute_features(requests: list[tuple[float, str, str, int]]) -> dict:
    ordered    = sorted(requests, key=lambda r: r[0])
    n          = len(ordered)
    timestamps = [r[0] for r in ordered]
    methods    = [r[1] for r in ordered]
    paths      = [r[2] for r in ordered]
    sizes      = [float(r[3]) for r in ordered]

    iats_ms = [
        (timestamps[i] - timestamps[i - 1]) * 1000.0
        for i in range(1, n)
        if timestamps[i] >= timestamps[i - 1]
    ]
    duration_s = max((timestamps[-1] - timestamps[0]) if n >= 2 else 0.0, 1.0)
    iat_mean   = statistics.fmean(iats_ms) if iats_ms else 0.0
    iat_std    = statistics.pstdev(iats_ms) if len(iats_ms) > 1 else 0.0

    return {
        "iat_mean_ms":         round(iat_mean, 4),
        "iat_cv":              round(iat_std / iat_mean, 6) if iat_mean > 0 else 0.0,
        "iat_bowley_skewness": round(_bowley(iats_ms), 6),
        "iat_mad_ms":          round(_mad(iats_ms), 4),
        "requests_per_hour":   round(min(n / (duration_s / 3600.0), 100_000.0), 4),
        "payload_size_mean":   round(statistics.fmean(sizes), 4) if sizes else 0.0,
        "payload_size_std":    round(statistics.pstdev(sizes), 4) if len(sizes) > 1 else 0.0,
        "http_post_ratio":     round(sum(1 for m in methods if m == "POST") / n, 6),
        "url_path_entropy":    round(_shannon_entropy(paths), 6),
        "request_burst_count": _burst_count(timestamps),
    }


# ── Session processing ─────────────────────────────────────────────────────────

def process_sessions(
    log_sessions: dict[str, list],
    label_map: dict[str, int],
    phase: int,
) -> list[dict]:
    rows: list[dict] = []
    skipped_short = 0
    skipped_missing = 0
    for sid, label in label_map.items():
        requests = log_sessions.get(sid)
        if not requests:
            skipped_missing += 1
            continue
        if len(requests) < MIN_REQUESTS:
            skipped_short += 1
            continue
        feats = compute_features(requests)
        row = {
            "session_id":    sid,
            "phase":         phase,
            "label":         label,
            "request_count": len(requests),
        }
        row.update(feats)
        rows.append(row)
    if skipped_missing:
        print(f"    Skipped {skipped_missing} annotated sessions not found in logs")
    if skipped_short:
        print(f"    Skipped {skipped_short} sessions with < {MIN_REQUESTS} requests")
    return rows


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    print()
    print(SEP)
    print("  C3 Web-Bot Dataset Extraction")
    print(f"  Source : {DATASET_ROOT}")
    print(f"  Output : {OUTPUT_CSV}")
    print(f"  Min    : {MIN_REQUESTS} requests per session")
    print(SEP)

    if not DATASET_ROOT.exists():
        sys.exit(f"\nDataset not found at: {DATASET_ROOT}\n"
                 "Check the DATASET_ROOT path in this script.")

    # ── Phase 1 ───────────────────────────────────────────────────────────────
    print("\n[Phase 1] Loading annotations ...")
    p1_ann = DATASET_ROOT / "phase1" / "annotations"
    phase1_labels = load_annotations(
        p1_ann / "humans_and_advanced_bots"  / "train",
        p1_ann / "humans_and_advanced_bots"  / "test",
        p1_ann / "humans_and_moderate_bots"  / "train",
        p1_ann / "humans_and_moderate_bots"  / "test",
        strip_suffix=False,
    )
    n1_h = sum(1 for v in phase1_labels.values() if v == 0)
    n1_b = sum(1 for v in phase1_labels.values() if v == 1)
    print(f"  Labeled sessions: {len(phase1_labels):,}  "
          f"(human={n1_h}  bot={n1_b})")

    print("\n[Phase 1] Parsing log files ...")
    p1_logs = (
        sorted((DATASET_ROOT / "phase1" / "data" / "web_logs" / "bots").glob("*.log")) +
        sorted((DATASET_ROOT / "phase1" / "data" / "web_logs" / "humans").glob("*.log"))
    )
    p1_sessions = collect_sessions(p1_logs, allowed=set(phase1_labels.keys()))
    print(f"  Sessions found in logs: {len(p1_sessions):,}")

    rows_p1 = process_sessions(p1_sessions, phase1_labels, phase=1)
    rp1_h = sum(1 for r in rows_p1 if r["label"] == 0)
    rp1_b = sum(1 for r in rows_p1 if r["label"] == 1)
    print(f"  Rows extracted: {len(rows_p1):,}  (human={rp1_h}  bot={rp1_b})")

    # ── Phase 2 ───────────────────────────────────────────────────────────────
    print("\n[Phase 2] Loading annotations ...")
    p2_ann = (DATASET_ROOT / "phase2" / "annotations"
              / "humans_and_moderate_and_advanced_bots"
              / "humans_and_moderate_and_advanced_bots")
    phase2_labels = load_annotations(p2_ann, strip_suffix=True)
    n2_h = sum(1 for v in phase2_labels.values() if v == 0)
    n2_b = sum(1 for v in phase2_labels.values() if v == 1)
    print(f"  Labeled sessions: {len(phase2_labels):,}  "
          f"(human={n2_h}  bot={n2_b})")

    print("\n[Phase 2] Parsing log files ...")
    p2_logs = (
        sorted((DATASET_ROOT / "phase2" / "data" / "web_logs" / "bots").glob("*.log")) +
        sorted((DATASET_ROOT / "phase2" / "data" / "web_logs" / "humans").glob("*.log"))
    )
    p2_sessions = collect_sessions(p2_logs, allowed=set(phase2_labels.keys()))
    print(f"  Sessions found in logs: {len(p2_sessions):,}")

    rows_p2 = process_sessions(p2_sessions, phase2_labels, phase=2)
    rp2_h = sum(1 for r in rows_p2 if r["label"] == 0)
    rp2_b = sum(1 for r in rows_p2 if r["label"] == 1)
    print(f"  Rows extracted: {len(rows_p2):,}  (human={rp2_h}  bot={rp2_b})")

    # ── Write CSV ─────────────────────────────────────────────────────────────
    all_rows = rows_p1 + rows_p2
    if not all_rows:
        sys.exit("\nNo sessions extracted. Verify DATASET_ROOT and annotation files.")

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(all_rows)

    total   = len(all_rows)
    n_human = rp1_h + rp2_h
    n_bot   = rp1_b + rp2_b

    print()
    print(SEP)
    print(f"  Output  : {OUTPUT_CSV}")
    print(f"  Total   : {total:,} sessions")
    print(f"  Human   : {n_human:,}  ({n_human / total * 100:.1f}%)")
    print(f"  Bot     : {n_bot:,}  ({n_bot / total * 100:.1f}%)")
    print(f"  Phase 1 : {len(rows_p1):,} sessions  (human={rp1_h}  bot={rp1_b})")
    print(f"  Phase 2 : {len(rows_p2):,} sessions  (human={rp2_h}  bot={rp2_b})")
    print()
    print("  Features (10 of 14 C3 features extracted from server logs):")
    for col in FEATURE_COLS:
        print(f"    {col}")
    print()
    print("  NOT available from server logs (require live CDP session):")
    print("    avg_idle_time_ms, user_active_ratio,")
    print("    background_tab_ratio, extension_origin_ratio")
    print(SEP)
    print()
    print("Next step: run scripts/train_c3_rf_model.py  (or train_c3_rf.bat)")
    print()


if __name__ == "__main__":
    main()
