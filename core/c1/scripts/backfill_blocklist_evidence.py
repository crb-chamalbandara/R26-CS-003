"""
Backfill missing evidence across the finalized blocklist sheet.

The live intercept path documents a blocklist row the moment someone tries to
install that extension. This script does the same thing offline for every row
that still has gaps, so the sheet stops shipping "Not Found" / "Not yet
confirmed" / "Not Confirmed" cells to the Blocklist Match panel.

For each ID it downloads the CRX from the Chrome Web Store, runs the same
detection stack C1 runs live (33 features -> XGBoost -> rule boosters ->
Isolation Forest, plus the dynamic sandbox with --sandbox), derives the threat
class from what those observed, and writes the completed row back to
`malext_sentry and chrome_mal_ids Finalized Blocklist IDs.csv`. Every field it
writes is also appended to `blocklist_enrichment_log.csv` with the old value,
the new value, the confidence and the method — so any cell can be traced back
to the run that produced it.

Rows whose extension the store has already removed come back "unavailable" and
are left exactly as they were: a delisted extension gives us nothing to observe,
and inventing evidence for it would be worse than an honest gap.

Usage (from the repo root, with the venv active):
    python -m core.c1.scripts.backfill_blocklist_evidence --limit 50
    python -m core.c1.scripts.backfill_blocklist_evidence --all --concurrency 6
    python -m core.c1.scripts.backfill_blocklist_evidence --limit 10 --sandbox
    python -m core.c1.scripts.backfill_blocklist_evidence --ids abc...,def...
    python -m core.c1.scripts.backfill_blocklist_evidence --limit 20 --dry-run

Flags:
    --limit N       document at most N undocumented rows (default 25)
    --all           document every undocumented row (thousands — takes hours)
    --ids A,B,C     document these specific extension IDs
    --sandbox       also run the dynamic sandbox (~20 s each, forces serial)
    --concurrency N parallel downloads when the sandbox is off (default 4)
    --dry-run       analyse and report, but do not touch the CSV
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from collections import Counter
from typing import List

if sys.platform == "win32":
    # Playwright needs the Proactor loop to spawn Chromium (same reason
    # core/main.py sets this at import time).
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from core.c1.analyzer import (            # noqa: E402  (must follow the loop policy)
    blocklist_coverage, blocklist_incomplete_ids, document_blocklist_entry,
)

_STATUS_ICON = {
    "documented":         "+",
    "no_change":          ".",
    "already_documented": "=",
    "unavailable":        "x",
    "not_blocklisted":    "?",
}


async def _document(ext_id: str, sandbox: bool, persist: bool, tally: Counter,
                    lock: asyncio.Lock) -> None:
    try:
        result = await document_blocklist_entry(
            ext_id, run_sandbox_layer=sandbox, persist=persist)
    except Exception as exc:                       # never let one bad CRX stop the sweep
        result = {"status": "unavailable", "ext_id": ext_id, "error": str(exc)}

    status = result["status"]
    tally[status] += 1
    entry = result.get("entry") or {}
    async with lock:                               # keep console lines from interleaving
        line = f"  [{_STATUS_ICON.get(status, ' ')}] {ext_id}  {status}"
        if status == "documented":
            reason = entry.get("reason") or "-"
            conf   = (result.get("reason_detail") or {}).get("confidence", "-")
            line += (f"  ->  {entry.get('extension_name') or '(no name)'}"
                     f"  |  {reason} ({conf})"
                     f"  |  filled: {', '.join(result.get('filled', []))}")
        elif status == "unavailable":
            line += f"  ({str(result.get('error', ''))[:70]})"
        print(line, flush=True)


async def run(ext_ids: List[str], sandbox: bool, concurrency: int, persist: bool) -> Counter:
    tally: Counter = Counter()
    lock = asyncio.Lock()
    # A sandbox run launches headed Chromium — those must not overlap.
    semaphore = asyncio.Semaphore(1 if sandbox else max(1, concurrency))

    async def guarded(ext_id: str) -> None:
        async with semaphore:
            await _document(ext_id, sandbox, persist, tally, lock)

    await asyncio.gather(*(guarded(ext_id) for ext_id in ext_ids))
    return tally


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--limit", type=int, default=25,
                        help="document at most this many undocumented rows (default 25)")
    parser.add_argument("--all", action="store_true",
                        help="document every undocumented row (overrides --limit)")
    parser.add_argument("--ids", default="",
                        help="comma-separated extension IDs to document instead of a scan")
    parser.add_argument("--sandbox", action="store_true",
                        help="also run the dynamic sandbox (~20 s per extension, serial)")
    parser.add_argument("--concurrency", type=int, default=4,
                        help="parallel downloads when the sandbox is off (default 4)")
    parser.add_argument("--dry-run", action="store_true",
                        help="analyse and report without writing to the CSV")
    args = parser.parse_args()

    before = blocklist_coverage()
    print("Finalized blocklist coverage")
    print(f"  sheet       : {before['sheet_path']}")
    print(f"  rows        : {before['total']}")
    print(f"  documented  : {before['documented']}  ({before['coverage_pct']}%)")
    print(f"  with gaps   : {before['incomplete']}")
    print(f"  missing     : {before['missing_by_field']}")
    print()

    if args.ids:
        ext_ids = [i.strip().lower() for i in args.ids.split(",") if i.strip()]
    else:
        ext_ids = blocklist_incomplete_ids(0 if args.all else max(0, args.limit))

    if not ext_ids:
        print("Nothing to document — every row already carries evidence.")
        return 0

    mode = "sandbox + ML" if args.sandbox else "ML only"
    print(f"Documenting {len(ext_ids)} row(s)  [{mode}"
          f"{', dry run — CSV untouched' if args.dry_run else ''}]")
    tally = asyncio.run(run(ext_ids, args.sandbox, args.concurrency, not args.dry_run))

    print()
    print("Result")
    for status, count in tally.most_common():
        print(f"  {status:<20} {count}")

    if not args.dry_run:
        after = blocklist_coverage()
        print()
        print(f"Coverage {before['coverage_pct']}% -> {after['coverage_pct']}%  "
              f"({after['documented'] - before['documented']:+d} rows documented)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
