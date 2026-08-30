"""
C3 feature engine.

Computes the 16 browser-aware C2 beacon features from per-host rolling
request windows.
"""
from __future__ import annotations

import math
import statistics
from urllib.parse import urlparse

import tldextract

# Frozen/offline extractor: suffix_list_urls=() disables the live network
# fetch of the public suffix list tldextract does by default, so feature
# scoring never depends on internet access and never blocks on a request.
# Built once at import time (not per-call) since constructing it parses the
# bundled suffix-list snapshot.
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


# The names of all 16 features. List ORDER here is purely for CSV/display
# layout — the RF classifier looks features up BY NAME (see RF_FEATURE_SUBSET
# in anomaly_engine.py and C3RFClassifierEngine.score()), never by position,
# so reordering this list cannot break the trained model.
FEATURE_ORDER = [
    "iat_mean_ms",           # average gap between requests (milliseconds)
    "iat_cv",                # how regular the gaps are (0 = clockwork, 1+ = random)
    "iat_bowley_skewness",   # whether the timing gaps skew early or late
    "iat_mad_ms",            # median absolute deviation of gaps — robust timing spread
    "requests_per_hour",     # how many requests per hour this host receives
    "payload_size_mean",     # average response/request size in bytes
    "payload_size_std",      # how much the payload size varies
    "http_post_ratio",       # fraction of requests that are POST (vs GET)
    "avg_idle_time_ms",      # average user idle time across all requests to this host
    "user_active_ratio",     # fraction of requests where the user was actively engaged
    "background_tab_ratio",  # fraction of requests that came from a hidden tab
    "extension_origin_ratio",# fraction of requests initiated by a browser extension
    "url_path_entropy",      # how many different URL paths are being called
    "request_burst_count",   # number of rapid-fire bursts (3+ requests within 2 seconds)
    # Deterministic browser-ground-truth signals (Plane 2). Appended after
    # the original 14 — the RF only reads the 7 it was trained on, by name
    # (see anomaly_engine.py), so appending names here never requires
    # retraining or re-indexing anything.
    "same_site_ratio",       # fraction of requests whose destination shares an eTLD+1 with the page the user was on
    "script_initiator_ratio",# fraction of requests whose CDP initiator.type == "script" (vs parser/preload/other)
]


# requests_per_hour is extrapolated from the window's observed span (see below).
# A floor shorter than this lets a page-load burst (e.g. 20 requests in 2 seconds)
# extrapolate into an astronomical, meaningless rate (20 / (2s/3600s) = 36,000/hr).
# Flooring the denominator at 60s bounds that same burst to a sane 1,200/hr instead.
# This floor can only ever LOWER the computed rate versus the raw span (never raise
# it further), so it cannot inflate any currently-correct value — it only removes
# the tiny-span-extrapolation failure mode.
_MIN_RATE_WINDOW_S = 60.0


def _etld1_from_host(host: str) -> str:
    """
    Registrable domain (eTLD+1) from an already-clean hostname, e.g.
    "edgeapi.slack.com" -> "slack.com". Uses the real public suffix list so
    compound TLDs are handled correctly — a naive "last two labels" compare
    would wrongly call "evil.co.uk" and "other.co.uk" the same site, which
    would suppress a real detection rather than a false positive.
    Returns "" on anything unparseable so callers can exclude it rather
    than guess.
    """
    if not host:
        return ""
    try:
        result = _TLD_EXTRACTOR(host)
    except Exception:
        return ""
    if not result.domain or not result.suffix:
        return ""
    return f"{result.domain}.{result.suffix}".lower()


def _etld1_from_url(url: str) -> str:
    """Registrable domain (eTLD+1) from a full URL — extracts the host first."""
    if not url:
        return ""
    try:
        hostname = urlparse(url).hostname or ""
    except Exception:
        return ""
    return _etld1_from_host(hostname)


def _safe_float(value, default: float = 0.0) -> float:
    """
    Convert to float, rejecting NaN/Inf rather than propagating them.
    statistics.pstdev/median raise StatisticsError on inf/nan inputs, which
    would otherwise crash compute_features() for an ENTIRE analyzer cycle
    (all hosts, not just the one with the bad event) over a single malformed
    reading. The live CDP path already int()-casts sizes upstream (which
    itself rejects nan/inf), but this is defense in depth for any other
    caller -- collection-mode data, tests, future code paths.
    """
    try:
        f = float(value)
    except (TypeError, ValueError):
        return default
    return f if math.isfinite(f) else default


def compute_features(events: list[dict]) -> dict:
    """
    Turn a list of raw request events into the 16 numeric features.
    events — the rolling window for one host (up to 50 entries).
    """
    # Sort by timestamp so inter-arrival times are computed in the right order.
    ordered = sorted(events, key=lambda item: _safe_float(item.get("timestamp", 0.0)))
    n = len(ordered)
    timestamps = [_safe_float(item.get("timestamp", 0.0)) for item in ordered]

    # Inter-Arrival Times (IATs) — the gap in milliseconds between consecutive requests.
    # These are the core timing features.  A perfectly regular beacon has tiny IAT variance.
    iats_ms = [
        (timestamps[idx] - timestamps[idx - 1]) * 1000.0
        for idx in range(1, len(timestamps))
        if timestamps[idx] >= timestamps[idx - 1]
    ]

    # Total observation window in seconds, floored at _MIN_RATE_WINDOW_S so a short
    # page-load burst cannot extrapolate requests_per_hour into an absurd value.
    duration_s = max((timestamps[-1] - timestamps[0]) if n >= 2 else 0.0, _MIN_RATE_WINDOW_S)

    payload_sizes = [_safe_float(item.get("size_bytes")) for item in ordered]
    idle_times    = [_safe_float(item.get("idle_time_ms")) for item in ordered]
    methods       = [str(item.get("method") or "GET").upper() for item in ordered]
    # Include query strings in path diversity — two calls to /beacon?ts=1 and
    # /beacon?ts=2 count as different paths, giving high entropy (safe-looking).
    # Two calls to the exact same /beacon endpoint count as one path → low entropy (beacon-like).
    paths         = [_path_for_entropy(str(item.get("url") or "")) for item in ordered]

    iat_mean = statistics.fmean(iats_ms) if iats_ms else 0.0
    iat_std  = statistics.pstdev(iats_ms) if len(iats_ms) > 1 else 0.0

    # same_site_ratio: only counts events where BOTH the destination host and
    # the active page URL parsed to a real eTLD+1. Events where page_url is
    # missing/unparseable (e.g. worker-initiated requests with no visible
    # tab) are excluded from the denominator entirely rather than guessed as
    # a match or mismatch — consistent with not fabricating unknown values.
    same_site_total = 0
    same_site_matches = 0
    script_initiated = 0
    for item in ordered:
        dest_etld1 = _etld1_from_host(str(item.get("host") or ""))
        page_etld1 = _etld1_from_url(str(item.get("page_url") or ""))
        if dest_etld1 and page_etld1:
            same_site_total += 1
            if dest_etld1 == page_etld1:
                same_site_matches += 1
        if str(item.get("initiator_type") or "") == "script":
            script_initiated += 1

    return {
        # Timing features — the most important for detecting C2 beacons
        "iat_mean_ms":          round(iat_mean, 4),
        # Coefficient of Variation: std / mean.  Near 0 means every gap is
        # almost the same length — the hallmark of a programmatic timer.
        "iat_cv":               round(iat_std / iat_mean, 6) if iat_mean > 0 else 0.0,
        "iat_bowley_skewness":  round(_bowley_skewness(iats_ms), 6),
        "iat_mad_ms":           round(_median_absolute_deviation(iats_ms), 4),
        # Request rate
        "requests_per_hour":    round(min(n / (duration_s / 3600.0), 100_000.0), 4),
        # Payload size — real C2 beacons tend to send small, uniform packets
        "payload_size_mean":    round(statistics.fmean(payload_sizes), 4) if payload_sizes else 0.0,
        "payload_size_std":     round(statistics.pstdev(payload_sizes), 4) if len(payload_sizes) > 1 else 0.0,
        # HTTP method — many C2 frameworks use POST to exfiltrate data
        "http_post_ratio":      round(sum(1 for m in methods if m == "POST") / n, 6) if n else 0.0,
        # Browser-context features — unique to C3, unavailable to network-layer IDS
        "avg_idle_time_ms":     round(statistics.fmean(idle_times), 4) if idle_times else 0.0,
        "user_active_ratio":    round(sum(1 for item in ordered if item.get("user_was_active")) / n, 6) if n else 0.0,
        "background_tab_ratio": round(sum(1 for item in ordered if item.get("is_background_tab")) / n, 6) if n else 0.0,
        "extension_origin_ratio": round(sum(1 for item in ordered if item.get("is_extension_origin")) / n, 6) if n else 0.0,
        # URL diversity — a beacon calls the same endpoint repeatedly (low entropy)
        "url_path_entropy":     round(_path_diversity_entropy(paths), 6),
        # Burst detection — a page load causes many requests in < 2 seconds
        "request_burst_count":  _burst_count(timestamps),
        # Deterministic browser ground-truth (Plane 2) — measured, not learned.
        # Defaults to 0.0 when no valid (destination, page) pair exists, which
        # is the conservative choice: an unknown same-site relationship must
        # never be treated as a same-site match.
        "same_site_ratio":      round(same_site_matches / same_site_total, 6) if same_site_total else 0.0,
        "script_initiator_ratio": round(script_initiated / n, 6) if n else 0.0,
    }


def _path_for_entropy(url: str) -> str:
    """Extract path + query string from a URL for diversity measurement."""
    try:
        parsed = urlparse(url)
        value = parsed.path or "/"
        if parsed.query:
            value += "?" + parsed.query
        return value
    except Exception:
        return "/"


def _median_absolute_deviation(values: list[float]) -> float:
    """
    MAD — the median of the absolute distances from the median.
    More robust than standard deviation: one outlier barely affects it,
    whereas std is pulled strongly by outliers.  A beacon with perfectly
    regular timing has MAD near 0.
    """
    if not values:
        return 0.0
    median = statistics.median(values)
    return float(statistics.median([abs(value - median) for value in values]))


def _bowley_skewness(values: list[float]) -> float:
    """
    Bowley skewness uses quartiles instead of the mean — robust to outliers.
    A value near 0 means the distribution is symmetric (even spread of gaps).
    Positive means gaps tend to be short (fast pulses).
    Negative means gaps tend to be long (slow pulses with occasional fast ones).
    """
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
    """Linear interpolation percentile on a sorted list."""
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
    """
    Shannon entropy measures information content / randomness.
    High entropy = many different characters (complex, varied text).
    Low entropy = few different characters (repetitive, predictable text).
    Used here to detect obfuscated code in extensions.
    """
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


def _path_diversity_entropy(paths: list[str]) -> float:
    """
    Shannon entropy over the distribution of unique URL paths.

    Measures how many distinct endpoints are being called, not character-level
    diversity. Repeated calls to the same URL → entropy 0.0 (single endpoint,
    beacon-like). Ten different endpoints → log2(10) ≈ 3.32 (varied, normal).
    """
    if not paths:
        return 0.0
    total = len(paths)
    counts: dict[str, int] = {}
    for p in paths:
        counts[p] = counts.get(p, 0) + 1
    entropy = 0.0
    for count in counts.values():
        prob = count / total
        entropy -= prob * math.log2(prob)
    return entropy


def _burst_count(timestamps: list[float]) -> int:
    """
    Count how many request bursts occurred.
    A burst is 3 or more requests arriving within a 2-second window.
    Page loads normally produce 1–2 bursts; steady beaconing produces 0.
    """
    count = 0
    i = 0
    ordered = sorted(timestamps)
    while i <= len(ordered) - 3:
        if ordered[i + 2] - ordered[i] <= 2.0:
            count += 1
            # Skip past the entire burst before looking for the next one.
            j = i + 3
            while j < len(ordered) and ordered[j] - ordered[i] <= 2.0:
                j += 1
            i = j
        else:
            i += 1
    return count


# =============================================================================
# WHAT THIS FILE DOES — plain English summary
# =============================================================================
#
# This file converts raw captured requests into 16 numbers that describe
# the traffic pattern for one destination host.
#
# Think of it like a medical lab taking a blood sample and running tests.
# The "blood sample" is the list of the last 50 requests to a particular host.
# The "test results" are the 14 feature values.
#
# The most important features for detecting C2 beacons are:
#
#   iat_cv (timing regularity)
#     Close to 0 means every request arrived at almost exactly the same
#     interval — like a metronome.  That is what a programmatic timer does.
#     Human browsing is irregular, so iat_cv is usually > 0.3.
#
#   user_active_ratio
#     Close to 0 means the requests fired while the user was idle or the tab
#     was hidden — a strong beacon signal.  Close to 1 means the user was
#     actively clicking around each time the request fired.
#
#   background_tab_ratio
#     How often the requests came from a tab the user was not looking at.
#     C2 malware almost always hides in background tabs.
#
#   url_path_entropy
#     How many different URLs are being called.  A beacon calls the same
#     endpoint over and over (low entropy = suspicious).  A normal user
#     visits many different pages (high entropy = safe).
#
# The ML models and heuristic rules in analyzer.py read these 14 numbers
# and decide whether the traffic looks like a C2 beacon.
# =============================================================================
