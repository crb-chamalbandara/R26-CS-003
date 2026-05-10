"""
C3 feature engine.

Computes the 14 browser-aware C2 beacon features from per-host rolling
request windows.
"""
from __future__ import annotations

import math
import statistics
from urllib.parse import urlparse


FEATURE_ORDER = [
    "iat_mean_ms",
    "iat_cv",
    "iat_bowley_skewness",
    "iat_mad_ms",
    "requests_per_hour",
    "payload_size_mean",
    "payload_size_std",
    "http_post_ratio",
    "avg_idle_time_ms",
    "user_active_ratio",
    "background_tab_ratio",
    "extension_origin_ratio",
    "url_path_entropy",
    "request_burst_count",
]


def compute_features(events: list[dict]) -> dict:
    ordered = sorted(events, key=lambda item: float(item.get("timestamp", 0.0)))
    n = len(ordered)
    timestamps = [float(item.get("timestamp", 0.0)) for item in ordered]
    iats_ms = [
        (timestamps[idx] - timestamps[idx - 1]) * 1000.0
        for idx in range(1, len(timestamps))
        if timestamps[idx] >= timestamps[idx - 1]
    ]

    duration_s = max((timestamps[-1] - timestamps[0]) if n >= 2 else 0.0, 1.0)
    payload_sizes = [float(item.get("size_bytes") or 0.0) for item in ordered]
    idle_times = [float(item.get("idle_time_ms") or 0.0) for item in ordered]
    methods = [str(item.get("method") or "GET").upper() for item in ordered]
    paths = [_path_for_entropy(str(item.get("url") or "")) for item in ordered]

    iat_mean = statistics.fmean(iats_ms) if iats_ms else 0.0
    iat_std = statistics.pstdev(iats_ms) if len(iats_ms) > 1 else 0.0

    return {
        "iat_mean_ms": round(iat_mean, 4),
        "iat_cv": round(iat_std / iat_mean, 6) if iat_mean > 0 else 0.0,
        "iat_bowley_skewness": round(_bowley_skewness(iats_ms), 6),
        "iat_mad_ms": round(_median_absolute_deviation(iats_ms), 4),
        "requests_per_hour": round(min(n / (duration_s / 3600.0), 100_000.0), 4),
        "payload_size_mean": round(statistics.fmean(payload_sizes), 4) if payload_sizes else 0.0,
        "payload_size_std": round(statistics.pstdev(payload_sizes), 4) if len(payload_sizes) > 1 else 0.0,
        "http_post_ratio": round(sum(1 for m in methods if m == "POST") / n, 6) if n else 0.0,
        "avg_idle_time_ms": round(statistics.fmean(idle_times), 4) if idle_times else 0.0,
        "user_active_ratio": round(sum(1 for item in ordered if item.get("user_was_active")) / n, 6) if n else 0.0,
        "background_tab_ratio": round(sum(1 for item in ordered if item.get("is_background_tab")) / n, 6) if n else 0.0,
        "extension_origin_ratio": round(sum(1 for item in ordered if item.get("is_extension_origin")) / n, 6) if n else 0.0,
        "url_path_entropy": round(_shannon_entropy("".join(paths)), 6),
        "request_burst_count": _burst_count(timestamps),
    }


def _path_for_entropy(url: str) -> str:
    try:
        parsed = urlparse(url)
        value = parsed.path or "/"
        if parsed.query:
            value += "?" + parsed.query
        return value
    except Exception:
        return "/"


def _median_absolute_deviation(values: list[float]) -> float:
    if not values:
        return 0.0
    median = statistics.median(values)
    return float(statistics.median([abs(value - median) for value in values]))


def _bowley_skewness(values: list[float]) -> float:
    if len(values) < 3:
        return 0.0
    ordered = sorted(values)
    q1 = _percentile(ordered, 25)
    q2 = _percentile(ordered, 50)
    q3 = _percentile(ordered, 75)
    denom = q3 - q1
    if denom == 0:
        return 0.0
    return float((q3 + q1 - 2 * q2) / denom)


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    pos = (len(values) - 1) * pct / 100.0
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return float(values[lo])
    weight = pos - lo
    return float(values[lo] * (1 - weight) + values[hi] * weight)


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    total = len(text)
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _burst_count(timestamps: list[float]) -> int:
    count = 0
    i = 0
    ordered = sorted(timestamps)
    while i <= len(ordered) - 3:
        if ordered[i + 2] - ordered[i] <= 2.0:
            count += 1
            j = i + 3
            while j < len(ordered) and ordered[j] - ordered[i] <= 2.0:
                j += 1
            i = j
        else:
            i += 1
    return count
