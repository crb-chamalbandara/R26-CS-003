"""
TC-03b — Reputation-Override Fusion Verification (safe, read-only, optional)
=============================================================================
A companion to TC-03 that proves core/c3/risk_fusion.py's reputation
override (reputation >= 0.8 floors the fused score at 0.60 = BEACON) against
a REAL, currently-flagged malicious IP pulled live from a public threat-
intel feed -- without ever sending a single request TO that IP.

WHAT THIS SCRIPT DOES
----------------------
1. Asks AbuseIPDB's own public "blacklist" endpoint for a handful of IPs
   currently reported as abusive (a metadata query ABOUT those IPs).
2. Feeds one of them into C3's real, unmodified reputation engine
   (core/c3/reputation_engine.py, imported directly -- this script does not
   edit, monkeypatch, or duplicate any C3 file) exactly the way
   analyzer.py's _handle_beacon() does, to get a real combined score.
3. Feeds that real score into C3's real, unmodified fusion function
   (core/c3/risk_fusion.py) alongside a deliberately modest synthetic
   rf/heuristic pair, to show the override alone is sufficient to reach
   BEACON -- proving the override logic against live data, not a mocked
   number.

WHAT THIS SCRIPT NEVER DOES
-----------------------------
It never opens a connection TO the flagged IP -- no request, no
navigation, no packet is ever sent to it. Every network call this script
makes is asking a legitimate third-party threat-intelligence service
(AbuseIPDB / OTX / VirusTotal) for its existing, already-published opinion
of that address. This is the same category of activity as looking up a
phone number in a public directory -- it is standard, safe practice in
detection-engineering research and requires no special authorisation
beyond your own AbuseIPDB API key.

This script imports core/c3 modules directly (no HTTP, no running backend
required) and writes nothing back to any C3 file, database, or settings.

Run via:  python tc03b_reputation_override_verification.py
          python tc03b_reputation_override_verification.py --test-ip 1.2.3.4
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import httpx  # noqa: E402

from core.c3.reputation_engine import (  # noqa: E402
    c3_reputation_engine, set_abuseipdb_key, set_otx_key, set_virustotal_key,
)
from core.c3.risk_fusion import c3_risk_fusion  # noqa: E402

os.system("")
_R = "\033[0m"; _B = "\033[1m"; _D = "\033[2m"
RED = "\033[91m"; YEL = "\033[93m"; GRN = "\033[92m"; CYN = "\033[96m"; WHT = "\033[97m"

def c(t, *codes): return "".join(codes) + str(t) + _R
def divider(ch="-", col=CYN): print(c(ch*68, col))
def header(title):
    print(); divider("="); print(c(f"  {title}", _B, WHT)); divider("=")


def _load_configured_keys() -> dict:
    """Read core/settings.json read-only -- reuses whatever keys are already
    configured via the dashboard's Settings/Detection Lab panels instead of
    asking the researcher to re-enter them."""
    path = os.path.join(_ROOT, "core", "settings.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


async def _fetch_blacklist_candidates(abuseipdb_key: str, limit: int = 5) -> list[str]:
    """AbuseIPDB's public /blacklist endpoint -- a read-only list of IPs the
    community has reported, sorted by confidence. Requires an AbuseIPDB key;
    availability of this specific endpoint depends on account tier, so this
    is wrapped defensively and the script falls back to --test-ip if it
    cannot be reached."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            params={"confidenceMinimum": 90, "limit": limit},
            headers={"Key": abuseipdb_key, "Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json().get("data") or []
        return [row["ipAddress"] for row in data if row.get("ipAddress")]


async def main() -> None:
    ap = argparse.ArgumentParser(description="TC-03b: Reputation-override fusion verification")
    ap.add_argument("--test-ip", default=None,
                     help="Skip the live blacklist lookup and use this specific IP instead "
                          "(e.g. one you already know is flagged from a threat feed you trust)")
    ap.add_argument("--abuseipdb-key", default=None, help="Override the key from core/settings.json")
    ap.add_argument("--otx-key", default=None)
    ap.add_argument("--virustotal-key", default=None)
    args = ap.parse_args()

    header("TEST CASE 03b — Reputation-Override Fusion Verification")
    print()
    print(c("  This test never contacts the flagged IP itself -- it only asks", _D))
    print(c("  AbuseIPDB / OTX / VirusTotal for their existing opinion of it.", _D))
    print()

    configured = _load_configured_keys()
    abuseipdb_key = args.abuseipdb_key or configured.get("abuseipdb_key", "")
    otx_key = args.otx_key or configured.get("otx_key", "")
    virustotal_key = args.virustotal_key or configured.get("virustotal_key", "")
    set_abuseipdb_key(abuseipdb_key)
    set_otx_key(otx_key)
    set_virustotal_key(virustotal_key)

    if not abuseipdb_key:
        sys.exit(c("\n  [FAIL] No AbuseIPDB key found (core/settings.json or --abuseipdb-key). "
                    "Required for both the blacklist lookup and the reputation check.", RED))

    header("STEP 1 — Obtain a Real, Currently-Flagged IP")
    if args.test_ip:
        candidate = args.test_ip.strip()
        print(c(f"\n  Using researcher-supplied IP: {candidate}", WHT))
    else:
        print(c("\n  Querying AbuseIPDB's public blacklist (confidence >= 90)...", _D))
        try:
            candidates = await _fetch_blacklist_candidates(abuseipdb_key)
        except Exception as exc:
            sys.exit(c(f"\n  [FAIL] Could not reach the blacklist endpoint ({exc}).\n"
                        f"         This endpoint's availability depends on your AbuseIPDB plan.\n"
                        f"         Re-run with --test-ip <a-known-flagged-ip> instead.", RED))
        if not candidates:
            sys.exit(c("\n  [FAIL] Blacklist returned no candidates. Re-run with --test-ip.", RED))
        candidate = candidates[0]
        print(c(f"  Selected: {candidate}  (top of {len(candidates)} live-flagged candidates)", WHT))

    header("STEP 2 — Real Reputation Lookup (core/c3/reputation_engine.py, unmodified)")
    result = await c3_reputation_engine.score_beacon(candidate, f"http://{candidate}/")
    rep_score_str = f"{result['score']:.4f}"
    print(f"\n  Score    : {c(rep_score_str, _B, WHT)}")
    print(f"  Flagged  : {c(str(result['flagged']), GRN if result['flagged'] else RED)}")
    print(f"  Sources  : {result.get('sources', {})}")
    print(f"  Detail   : {result.get('detail', '')}")

    header("STEP 3 — Fusion Override Verification (core/c3/risk_fusion.py, unmodified)")
    # Deliberately modest rf/heuristic values -- the point is that reputation
    # ALONE, via the override, is enough to reach BEACON regardless of what
    # the other two signals say.
    fused = c3_risk_fusion.fuse(rf=0.3, reputation=result["score"], heuristic=0.2)
    fused_score_str = f"{fused['score']:.4f}"
    print(f"\n  Input    : rf=0.30, reputation={rep_score_str}, heuristic=0.20")
    print(f"  Score    : {c(fused_score_str, _B, WHT)}")
    print(f"  Verdict  : {c(fused['verdict'], _B, RED if fused['verdict']=='BEACON' else YEL)}")
    print(f"  Detail   : {fused['detail']}")

    header("STEP 4 — Pass/Fail")
    print()
    checks = [
        ("Blacklist/candidate IP resolved", bool(candidate)),
        ("Reputation engine flagged the IP (score >= 0.8)",
         result["flagged"] and result["score"] >= 0.8),
        ("Fusion score reached BEACON threshold via override alone",
         fused["verdict"] == "BEACON"),
        ("Override tag present in fusion detail",
         "override" in fused["detail"]),
    ]
    all_pass = True
    for name, ok in checks:
        icon = c("PASS", _B, GRN) if ok else c("FAIL", _B, RED)
        print(f"  [{icon}]  {name}")
        if not ok: all_pass = False
    print()
    divider("=")
    if all_pass:
        print(c("  TC-03b RESULT:  ALL CHECKS PASSED  ✓", _B, GRN))
    else:
        print(c("  TC-03b RESULT:  SOME CHECKS FAILED  ✗", _B, RED))
    divider("=")
    print()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(c("\n\n  Test stopped by user (Ctrl+C).", YEL))
        sys.exit(0)
