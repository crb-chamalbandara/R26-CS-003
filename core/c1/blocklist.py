"""
C1 — blocklist.py  |  The Blocklist Loader & Writer
---------------------------------------------------
Purpose : Load the finalized malicious-extension blocklist — extension IDs
          plus evidence metadata (name, reason, original reported source,
          date, store, version, SHA256 hash) — from the combined
          malext_sentry + chrome_mal_ids CSV, flag which rows are still
          undocumented, and write completed evidence back to the sheet.
Role    : Called once by analyzer.py at startup. Replaces the older
          malicious_ids.json (ID-only, no evidence) as the Step 2 hash
          check's data source.

Gaps and write-back
-------------------
Roughly a tenth of the sheet came from the ID-only `chrome-mal-ids` dump and
carries literal placeholder text — "Not Found" for the name and hash,
"Not yet confirmed" for the reason, "Not Confirmed" for store and version,
"N/A" for the date. Those strings are not evidence, so `entry_gaps()` marks
them as missing and the panel renders them as unknown rather than parroting
the placeholder. When a live intercept fills a gap in, `update_entry()`
writes the completed row back to this same CSV (and appends an audit line to
`blocklist_enrichment_log.csv`) so the record is documented from then on.
"""
from __future__ import annotations

import csv
import os
import threading
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple, TypedDict

# The sheet's header row, verbatim — including the "Extention Name" typo that
# the original export shipped with. Rewrites must preserve it exactly or Excel
# and every downstream script stop finding their columns.
HEADERS: List[str] = [
    "Extension ID", "Extention Name", "Reason", "Original Reported Source",
    "Date", "Store", "Version", "SHA256 Hash",
]

# entry key -> sheet column
FIELD_TO_COLUMN: Dict[str, str] = {
    "extension_name": "Extention Name",
    "reason":         "Reason",
    "source":         "Original Reported Source",
    "date":           "Date",
    "store":          "Store",
    "version":        "Version",
    "sha256":         "SHA256 Hash",
}

# Fields a live intercept is able to establish on its own.
ENRICHABLE_FIELDS: Tuple[str, ...] = (
    "extension_name", "reason", "date", "store", "version", "sha256",
)

# Cell values that carry no information. Everything here is treated as an
# empty cell by `is_missing()`, so the UI never shows "Not Confirmed" as if
# it were a finding. "Removal reason Unknown" is deliberately NOT in this
# set — that is a real, sourced reason used by 263 curated rows.
MISSING_TOKENS = frozenset({
    "", "-", "--", "—", "n/a", "na", "n\\a", "none", "null", "nil",
    "unknown", "not found", "notfound", "not confirmed", "notconfirmed",
    "not yet confirmed", "not-yet-confirmed", "tbd", "pending", "?",
})

_WRITE_LOCK = threading.Lock()
_LOG_HEADERS = [
    "timestamp", "extension_id", "field", "old_value", "new_value",
    "confidence", "method",
]


class BlocklistEntry(TypedDict, total=False):
    extension_name: str
    reason: str
    source: str
    source_is_url: bool
    date: str
    store: str
    version: str
    sha256: Optional[str]        # None when the sheet says "Not Found"
    # ── derived / runtime-only ────────────────────────────────────
    extension_id: str
    gaps: List[str]              # enrichable fields the sheet has no value for
    documented: bool             # True when the row has no gaps left
    enriched: bool               # True when this run filled something in
    enriched_fields: List[str]   # which columns this run wrote
    name_provenance: str         # manifest | manifest_i18n | webstore_slug
    reason_derived: bool         # reason came from the models, not the sheet
    reason_detail: Dict          # ReasonVerdict.as_dict() when derived
    evidence: Dict               # live observations backing the new values
    sheet_synced: bool           # the CSV on disk now carries these values


# ── Placeholder handling ──────────────────────────────────────────────────────

def is_missing(value: Optional[str]) -> bool:
    """True when a cell holds no usable information (blank or placeholder)."""
    return str(value or "").strip().lower() in MISSING_TOKENS


def _clean(value: Optional[str]) -> str:
    """Sheet cell -> real value, with placeholder text collapsed to empty."""
    text = str(value or "").strip()
    return "" if is_missing(text) else text


def entry_gaps(entry: Optional[BlocklistEntry]) -> List[str]:
    """Which enrichable fields this blocklist row still has no evidence for."""
    if not entry:
        return list(ENRICHABLE_FIELDS)
    return [name for name in ENRICHABLE_FIELDS if is_missing(entry.get(name) or "")]


# ── Load ──────────────────────────────────────────────────────────────────────

def load_blocklist(csv_path: str) -> Dict[str, BlocklistEntry]:
    """Read the finalized blocklist CSV and return {extension_id: entry}.

    The sheet is Excel-exported (Windows-1252 encoding, not UTF-8) — some
    entries contain en-dash/em-dash characters in the extension name that
    would raise UnicodeDecodeError under utf-8.

    Placeholder cells are normalised to empty strings and reported through
    ``entry["gaps"]``; the raw sheet text is never shown to the analyst.
    """
    entries: Dict[str, BlocklistEntry] = {}
    with open(csv_path, "r", encoding="cp1252", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            ext_id = (row.get("Extension ID") or "").strip().lower()
            if not ext_id:
                continue    # skip blank rows

            source = _clean(row.get("Original Reported Source"))
            entry: BlocklistEntry = {
                "extension_id":   ext_id,
                "extension_name": _clean(row.get("Extention Name")),
                "reason":         _clean(row.get("Reason")),
                "source":         source,
                "source_is_url":  source.lower().startswith(("http://", "https://")),
                "date":           _clean(row.get("Date")),
                "store":          _clean(row.get("Store")),
                "version":        _clean(row.get("Version")),
                "sha256":         _clean(row.get("SHA256 Hash")) or None,
            }
            gaps = entry_gaps(entry)
            entry["gaps"]       = gaps
            entry["documented"] = not gaps
            entry["enriched"]   = False
            entries[ext_id] = entry
    return entries


def blocklist_stats(entries: Dict[str, BlocklistEntry]) -> Dict:
    """Coverage summary for the dashboard: how much of the sheet is documented."""
    total = len(entries)
    per_field = {name: 0 for name in ENRICHABLE_FIELDS}
    incomplete = 0
    for entry in entries.values():
        gaps = entry.get("gaps") or entry_gaps(entry)
        if gaps:
            incomplete += 1
        for name in gaps:
            per_field[name] += 1
    return {
        "total":            total,
        "documented":       total - incomplete,
        "incomplete":       incomplete,
        "missing_by_field": per_field,
        "coverage_pct":     round((total - incomplete) / total * 100, 2) if total else 0.0,
    }


def incomplete_ids(entries: Dict[str, BlocklistEntry]) -> List[str]:
    """Every extension ID whose row still has at least one undocumented field."""
    return [ext_id for ext_id, entry in entries.items()
            if entry.get("gaps") or entry_gaps(entry)]


# ── Write-back ────────────────────────────────────────────────────────────────

def _log_path(csv_path: str) -> str:
    return os.path.join(os.path.dirname(csv_path), "blocklist_enrichment_log.csv")


def _append_audit(csv_path: str, ext_id: str, changes: Dict[str, Tuple[str, str]],
                  confidence: str, method: str) -> None:
    """Append one line per changed column so every sheet edit is traceable."""
    path = _log_path(csv_path)
    new_file = not os.path.exists(path)
    try:
        with open(path, "a", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            if new_file:
                writer.writerow(_LOG_HEADERS)
            stamp = datetime.now().isoformat(timespec="seconds")
            for field_name, (old, new) in changes.items():
                writer.writerow([stamp, ext_id, field_name, old, new, confidence, method])
    except OSError as exc:                                  # audit is best-effort
        print(f"[C1-BLOCKLIST] Could not write enrichment log: {exc}")


def update_entry(
    csv_path: str,
    ext_id: str,
    updates: Dict[str, str],
    *,
    overwrite: bool = False,
    confidence: str = "",
    method: str = "",
) -> List[str]:
    """Write filled-in evidence back into the finalized blocklist CSV.

    Only columns that are currently *missing* are written unless
    ``overwrite`` is set — curated evidence always wins over a live guess.
    Returns the list of entry field names actually changed (empty if the row
    was already complete or the ID isn't in the sheet).

    The rewrite is atomic (temp file + os.replace) and holds a process-wide
    lock, so a burst of concurrent intercepts can't interleave two rewrites
    of the same file.
    """
    ext_id = (ext_id or "").strip().lower()
    wanted = {k: str(v).strip() for k, v in (updates or {}).items()
              if k in FIELD_TO_COLUMN and str(v or "").strip()}
    if not ext_id or not wanted:
        return []

    with _WRITE_LOCK:
        try:
            with open(csv_path, "r", encoding="cp1252", newline="") as handle:
                reader = csv.DictReader(handle)
                fieldnames = reader.fieldnames or HEADERS
                rows = list(reader)
        except OSError as exc:
            print(f"[C1-BLOCKLIST] Could not read sheet for update: {exc}")
            return []

        changes: Dict[str, Tuple[str, str]] = {}
        target = None
        for row in rows:
            if (row.get("Extension ID") or "").strip().lower() == ext_id:
                target = row
                break
        if target is None:
            return []

        for field_name, value in wanted.items():
            column = FIELD_TO_COLUMN[field_name]
            current = str(target.get(column) or "").strip()
            if not overwrite and not is_missing(current):
                continue                       # curated value — leave it alone
            if current == value:
                continue
            target[column] = value
            changes[field_name] = (current, value)

        if not changes:
            return []

        tmp_path = f"{csv_path}.tmp"
        try:
            with open(tmp_path, "w", encoding="cp1252", errors="replace", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            os.replace(tmp_path, csv_path)
        except OSError as exc:
            print(f"[C1-BLOCKLIST] Sheet write failed for {ext_id}: {exc}")
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            return []

    _append_audit(csv_path, ext_id, changes, confidence, method)
    return list(changes.keys())


def apply_updates(entry: BlocklistEntry, updates: Dict[str, str],
                  *, overwrite: bool = False) -> List[str]:
    """Mirror a sheet update onto the in-memory entry. Returns changed fields."""
    changed: List[str] = []
    for field_name, value in (updates or {}).items():
        if field_name not in FIELD_TO_COLUMN:
            continue
        value = str(value or "").strip()
        if not value:
            continue
        if not overwrite and not is_missing(entry.get(field_name) or ""):
            continue
        if str(entry.get(field_name) or "") == value:
            continue
        entry[field_name] = value            # type: ignore[literal-required]
        changed.append(field_name)
    if "source" in changed:
        entry["source_is_url"] = str(entry.get("source") or "").lower().startswith(("http://", "https://"))
    if changed:
        entry["gaps"]       = entry_gaps(entry)
        entry["documented"] = not entry["gaps"]
    return changed


def iter_entries(entries: Dict[str, BlocklistEntry],
                 only_incomplete: bool = False) -> Iterable[BlocklistEntry]:
    for entry in entries.values():
        if only_incomplete and not (entry.get("gaps") or entry_gaps(entry)):
            continue
        yield entry
